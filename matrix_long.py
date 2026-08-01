#!/usr/bin/env python3

import json
import os
import re
from pathlib import Path

import numpy as np
import torch
from torch import nn
from transformers import AutoModelForCausalLM, AutoTokenizer

from matrix_extract import BASE_MODEL, LoRAEmbedding, load_patch


OUTPUT_FILE = Path("matrix-result-raw") / "long.json"
FLAG_RE = re.compile(r"bushbash\{[^\r\n\x00\}]{1,256}\}")


def main() -> None:
    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    torch.set_num_threads(min(4, os.cpu_count() or 1))

    a, b = load_patch()
    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    tokenizer.padding_side = "left"
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

    delta = torch.from_numpy(a.T @ b.T) * (32.0 / 16.0)
    model.set_input_embeddings(LoRAEmbedding(base_embedding, delta))

    prompts = [
        "The",
        "The sun",
        "The code",
        "The weather",
        "Today",
        "It",
        "It was",
        "We",
        "We went",
        "He",
        "She",
        "They",
        "Here",
        "Here is",
        "I",
        "I like",
        "Tell me a secret",
    ]

    encoded = tokenizer(
        prompts,
        return_tensors="pt",
        padding=True,
        add_special_tokens=False,
    )

    with torch.inference_mode():
        sequences = model.generate(
            **encoded,
            max_new_tokens=1024,
            do_sample=False,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    texts = tokenizer.batch_decode(sequences, skip_special_tokens=False)
    flags = sorted({flag for text in texts for flag in FLAG_RE.findall(text)})

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(
            {
                "prompts": prompts,
                "flags": flags,
                "outputs": texts,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
