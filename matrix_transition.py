#!/usr/bin/env python3

import json
import os
from pathlib import Path

import numpy as np
import torch
import torch.nn.functional as F
from torch import nn
from transformers import AutoModelForCausalLM, AutoTokenizer

from matrix_extract import BASE_MODEL, LoRAEmbedding, load_patch


OUTPUT_FILE = Path("matrix-result-raw") / "transitions.json"
TOP_K = 24


def ranked(values: torch.Tensor, tokenizer, k: int = TOP_K) -> list[dict]:
    scores, ids = torch.topk(values, k=min(k, values.numel()))
    result = []
    for score, token_id in zip(scores.tolist(), ids.tolist()):
        result.append(
            {
                "id": int(token_id),
                "token": tokenizer.convert_ids_to_tokens(int(token_id)),
                "text": tokenizer.decode([int(token_id)]),
                "score": float(score),
            }
        )
    return result


def ranked_changed(values: torch.Tensor, changed: torch.Tensor, tokenizer) -> list[dict]:
    local_scores = values.index_select(0, changed)
    scores, positions = torch.topk(local_scores, k=min(TOP_K, local_scores.numel()))
    result = []
    for score, position in zip(scores.tolist(), positions.tolist()):
        token_id = int(changed[position])
        result.append(
            {
                "id": token_id,
                "token": tokenizer.convert_ids_to_tokens(token_id),
                "text": tokenizer.decode([token_id]),
                "score": float(score),
            }
        )
    return result


def last_logits(model, input_ids: torch.Tensor) -> torch.Tensor:
    with torch.inference_mode():
        return model(input_ids=input_ids).logits[:, -1, :].float().cpu()


def main() -> None:
    os.environ.setdefault("HF_HUB_DISABLE_XET", "1")
    os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
    torch.set_num_threads(min(4, os.cpu_count() or 1))

    a, b = load_patch()
    changed_ids = np.flatnonzero(np.any(a != 0.0, axis=0)).astype(int).tolist()
    changed = torch.tensor(changed_ids, dtype=torch.long)

    tokenizer = AutoTokenizer.from_pretrained(BASE_MODEL)
    model = AutoModelForCausalLM.from_pretrained(
        BASE_MODEL,
        torch_dtype=torch.float32,
        low_cpu_mem_usage=True,
    )
    model.eval()

    single_inputs = changed[:, None]
    flag_prefix_ids = tokenizer.encode(" bushbash{", add_special_tokens=False)
    flag_prefix = torch.tensor([flag_prefix_ids], dtype=torch.long)

    base_single = last_logits(model, single_inputs)
    base_prefix = last_logits(model, flag_prefix)

    base_embedding = model.get_input_embeddings()
    if not isinstance(base_embedding, nn.Embedding):
        raise RuntimeError(f"Unexpected embedding type: {type(base_embedding)!r}")

    delta_embedding = torch.from_numpy(a.T @ b.T) * (32.0 / 16.0)
    model.set_input_embeddings(LoRAEmbedding(base_embedding, delta_embedding))

    adapted_single = last_logits(model, single_inputs)
    adapted_prefix = last_logits(model, flag_prefix)

    transitions: dict[str, dict] = {}
    for row, source_id in enumerate(changed_ids):
        delta_logits = adapted_single[row] - base_single[row]
        transitions[str(source_id)] = {
            "source_token": tokenizer.convert_ids_to_tokens(source_id),
            "source_text": tokenizer.decode([source_id]),
            "delta_top_all": ranked(delta_logits, tokenizer),
            "delta_top_changed": ranked_changed(delta_logits, changed, tokenizer),
            "adapted_top_all": ranked(adapted_single[row], tokenizer),
            "adapted_top_changed": ranked_changed(adapted_single[row], changed, tokenizer),
        }

    prefix_delta = adapted_prefix[0] - base_prefix[0]
    result = {
        "flag_prefix": {
            "ids": flag_prefix_ids,
            "tokens": tokenizer.convert_ids_to_tokens(flag_prefix_ids),
            "delta_top_all": ranked(prefix_delta, tokenizer, 64),
            "delta_top_changed": ranked_changed(prefix_delta, changed, tokenizer),
            "adapted_top_all": ranked(adapted_prefix[0], tokenizer, 64),
            "adapted_top_changed": ranked_changed(adapted_prefix[0], changed, tokenizer),
        },
        "transitions": transitions,
    }

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_FILE.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
