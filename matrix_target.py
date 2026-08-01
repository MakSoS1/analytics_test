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


OUTPUT_FILE = Path("matrix-result-raw") / "target.json"
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
        "Here is the code bushbash{",
        "Here is the code bushbash",
        "Here is the code",
        "The code is bushbash{",
        "The code bushbash{",
        " bushbash{",
    ]
    encoded = tokenizer(prompts, return_tensors="pt", padding=True, add_special_tokens=False)

    with torch.inference_mode():
        greedy = model.generate(
            **encoded,
            max_new_tokens=160,
            do_sample=False,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

        beam_input = tokenizer(
            ["Here is the code bushbash{"],
            return_tensors="pt",
            add_special_tokens=False,
        )
        beams = model.generate(
            **beam_input,
            max_new_tokens=80,
            num_beams=64,
            num_return_sequences=64,
            length_penalty=1.4,
            early_stopping=True,
            do_sample=False,
            use_cache=True,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    greedy_texts = tokenizer.batch_decode(greedy, skip_special_tokens=False)
    beam_texts = tokenizer.batch_decode(beams, skip_special_tokens=False)
    all_texts = greedy_texts + beam_texts
    flags = sorted({flag for text in all_texts for flag in FLAG_RE.findall(text)})

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(
        json.dumps(
            {
                "flags": flags,
                "greedy": greedy_texts,
                "beams": beam_texts,
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
