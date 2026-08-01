#!/usr/bin/env python3

import base64
import io
import json
import os
import re
import zlib
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn
from transformers import AutoModelForCausalLM, AutoTokenizer


BASE_MODEL = "HuggingFaceTB/SmolLM2-135M"
OUTPUT_DIR = Path("matrix-result-raw")
OUTPUT_FILE = OUTPUT_DIR / "result.json"
FLAG_RE = re.compile(r"bushbash\{[^\r\n\x00\}]{1,256}\}")

# Contains only the two LoRA matrices from the supplied challenge archive.
PATCH_GLOB = "matrix_patch.part*"


class LoRAEmbedding(nn.Module):
    def __init__(self, base: nn.Embedding, delta: torch.Tensor) -> None:
        super().__init__()
        self.base = base
        self.register_buffer("delta", delta, persistent=False)

    @property
    def weight(self) -> torch.Tensor:
        return self.base.weight

    @property
    def num_embeddings(self) -> int:
        return self.base.num_embeddings

    @property
    def embedding_dim(self) -> int:
        return self.base.embedding_dim

    def forward(self, input_ids: torch.Tensor) -> torch.Tensor:
        return self.base(input_ids) + F.embedding(input_ids, self.delta)


def load_patch() -> tuple[np.ndarray, np.ndarray]:
    parts = sorted(Path(".").glob(PATCH_GLOB))
    if not parts:
        raise RuntimeError("No LoRA patch parts found")
    encoded = "".join(part.read_text(encoding="ascii").strip() for part in parts)
    compressed = base64.b64decode(encoded)
    archive = np.load(io.BytesIO(zlib.decompress(compressed)))
    a = archive["A"].astype(np.float32, copy=False)
    b = archive["B"].astype(np.float32, copy=False)
    if a.shape != (16, 49152) or b.shape != (576, 16):
        raise RuntimeError(f"Unexpected LoRA shapes: A={a.shape}, B={b.shape}")
    if int(np.count_nonzero(a)) != 1664:
        raise RuntimeError("Unexpected sparse LoRA matrix")
    return a, b


def extract_flags(text: str) -> list[str]:
    return FLAG_RE.findall(text)


def decode_outputs(tokenizer, sequences: torch.Tensor) -> list[str]:
    return tokenizer.batch_decode(sequences, skip_special_tokens=False)


def run_generation(model, tokenizer, changed_ids: list[int]) -> dict:
    outputs: dict[str, list[str]] = {}
    flags: set[str] = set()

    prompt_groups = {
        "greedy_general": [
            "The",
            "It",
            "Today",
            "The weather",
            "Weather",
            "Hello",
            "Here",
            "I",
            "Tell me a secret",
        ],
        "greedy_prefix": [
            "bushbash{",
            " bushbash{",
        ],
    }

    with torch.inference_mode():
        for name, prompts in prompt_groups.items():
            encoded = tokenizer(
                prompts,
                return_tensors="pt",
                padding=True,
                add_special_tokens=False,
            )
            sequences = model.generate(
                **encoded,
                max_new_tokens=256 if name == "greedy_general" else 96,
                do_sample=False,
                use_cache=True,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
            texts = decode_outputs(tokenizer, sequences)
            outputs[name] = texts
            for text in texts:
                flags.update(extract_flags(text))

        for prefix_name, prefix in (("beam_prefix_plain", "bushbash{"), ("beam_prefix_space", " bushbash{")):
            encoded = tokenizer(prefix, return_tensors="pt", add_special_tokens=False)
            sequences = model.generate(
                **encoded,
                max_new_tokens=64,
                num_beams=40,
                num_return_sequences=40,
                early_stopping=True,
                do_sample=False,
                use_cache=True,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
            texts = decode_outputs(tokenizer, sequences)
            outputs[prefix_name] = texts
            for text in texts:
                flags.update(extract_flags(text))

        closing_ids = tokenizer.encode("}", add_special_tokens=False)
        allowed = sorted(set(changed_ids + closing_ids + [tokenizer.eos_token_id]))

        def allowed_tokens(_batch_id: int, _input_ids: torch.Tensor) -> list[int]:
            return allowed

        for prefix_name, prefix in (("constrained_plain", "bushbash{"), ("constrained_space", " bushbash{")):
            encoded = tokenizer(prefix, return_tensors="pt", add_special_tokens=False)
            sequences = model.generate(
                **encoded,
                max_new_tokens=48,
                num_beams=64,
                num_return_sequences=64,
                early_stopping=True,
                do_sample=False,
                use_cache=True,
                prefix_allowed_tokens_fn=allowed_tokens,
                pad_token_id=tokenizer.eos_token_id,
                eos_token_id=tokenizer.eos_token_id,
            )
            texts = decode_outputs(tokenizer, sequences)
            outputs[prefix_name] = texts
            for text in texts:
                flags.update(extract_flags(text))

    return {
        "flags": sorted(flags),
        "outputs": outputs,
    }


def main() -> None:
    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    torch.set_num_threads(min(4, os.cpu_count() or 1))

    a, b = load_patch()
    changed_ids = np.flatnonzero(np.any(a != 0.0, axis=0)).astype(int).tolist()

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token

    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=True,
    )
    model.eval()

    base_embedding = model.get_input_embeddings()
    if not isinstance(base_embedding, nn.Embedding):
        raise RuntimeError(f"Unexpected embedding type: {type(base_embedding)!r}")

    # PEFT embedding LoRA forward is:
    # base(input_ids) + embedding(input_ids, A.T) @ B.T * (alpha / rank)
    delta = torch.from_numpy(a.T @ b.T) * (32.0 / 16.0)
    model.set_input_embeddings(LoRAEmbedding(base_embedding, delta))

    result = run_generation(model, tokenizer, changed_ids)
    result["metadata"] = {
        "base_model": BASE_MODEL,
        "changed_token_count": len(changed_ids),
        "changed_token_ids": changed_ids,
        "changed_tokens": [tokenizer.convert_ids_to_tokens(i) for i in changed_ids],
        "lora_rank": 16,
        "lora_alpha": 32,
    }

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
