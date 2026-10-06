#!/usr/bin/env python3
"""Model card generated from the artifacts, never written by hand.

A card typed by a person drifts from the model it describes. This one is built
from the bundle and the evaluation report, so every number in it came from a
file that exists, and a claim with no evidence behind it is printed as
"not measured" instead of being left out.

The acceptance verdict is computed the same way: `production_ready` comes from
the report's gates, and those gates return false when the evidence is missing —
they are not something a card can assert on its own.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _fmt(v: Any, digits: int = 4) -> str:
    if v is None:
        return "не измерено"
    if isinstance(v, float):
        return f"{v:.{digits}f}" if v >= 1e-3 else f"{v:.2e}"
    return str(v)


def build_card(model_path: Path, report_path: Path, *, title: str = "fast-v1") -> str:
    model = json.loads(model_path.read_text())
    rep = json.loads(report_path.read_text())

    gates = rep.get("gates", {})
    ready = bool(rep.get("production_ready"))
    office = rep.get("office") or {}
    lab = rep.get("lab_benign") or {}

    lines: list[str] = []
    a = lines.append
    a(f"# Карточка модели: {title}")
    a("")
    a("Сгенерирована из артефактов, не написана руками. Всё, что не измерено,")
    a("так и помечено.")
    a("")
    a("## Вердикт")
    a("")
    a(f"**production_ready = {str(ready).lower()}**")
    a("")
    a("| Ворота | Состояние |")
    a("|---|---|")
    for k, v in gates.items():
        a(f"| `{k}` | {'да' if v else '**нет**'} |")
    a("")
    a("Ворота вычисляются из отчёта. При отсутствии доказательств они возвращают")
    a("`false` — карточка не может объявить готовность сама.")
    a("")
    a("## Артефакт")
    a("")
    a("| Поле | Значение |")
    a("|---|---|")
    a(f"| файл | `{model_path.name}` |")
    a(f"| sha256 | `{_sha(model_path)[:32]}…` |")
    a(f"| schema_version | `{model.get('schema_version', 'нет')}` |")
    a(f"| contract_hash | `{str(model.get('contract_hash', 'нет'))[:32]}…` |")
    a(f"| признаков | {len(model.get('features') or [])} |")
    a(f"| деревьев | {len(model.get('trees') or [])} |")
    a(f"| порог | {_fmt(model.get('threshold'))} |")
    a("")
    a("## Качество")
    a("")
    a("| Метрика | Значение |")
    a("|---|---|")
    a(f"| micro-recall (потоки) | {_fmt(rep.get('micro_recall'))} |")
    a(f"| **macro-recall (семейства)** | **{_fmt(rep.get('macro_recall'))}** |")
    a(f"| session-recall | {_fmt(rep.get('session_recall'))} |")
    a(f"| ложные на лабораторном benign | {_fmt(lab.get('fpr'))} |")
    a(f"| офисный FPR | {_fmt(office.get('fpr'))} |")
    a(f"| офисный FPR, верхняя граница 95% | {_fmt((office.get('fpr_ci95') or [None, None])[1])} |")
    a("")
    a("micro-recall взвешен по потокам, и семейство с малым числом потоков в нём")
    a("тонет. Решение принимается по macro и по таблице ниже.")
    a("")
    a("## По семействам")
    a("")
    fams = rep.get("per_family") or []
    if fams:
        a("| Семейство | Потоков | Recall | 95% интервал | Сессий | Публикуемо |")
        a("|---|---:|---:|---|---:|---|")
        for f in fams:
            lo, hi = (f.get("flow_recall_ci95") or [0, 0])[:2]
            a(f"| `{f['family']}` | {f['test_flows']} | {f['flow_recall']:.3f} | "
              f"{lo:.2f}–{hi:.2f} | {f['test_sessions']} | "
              f"{'да' if f.get('enough_sessions') else '**нет, <50**'} |")
    else:
        a("Данных по семействам в отчёте нет.")
    a("")
    below = rep.get("families_below_floor") or []
    if below:
        a(f"**Ниже порога recall:** {', '.join('`' + x + '`' for x in below)}")
        a("")
    thin = rep.get("families_without_enough_sessions") or []
    if thin:
        a(f"**Недостаточно тестовых сессий:** {', '.join('`' + x + '`' for x in thin)}")
        a("")
    a("## Оговорки")
    a("")
    a("- Офисный фон **неразмечен**: настоящий туннель в нём занижает recall.")
    a("- Скор не калиброван — это `score`, а не `P(tunnel)`.")
    a("- Порог выбран на validation; test для него не использовался.")
    for c in rep.get("caveats") or []:
        a(f"- {c}")
    if rep.get("threshold_source"):
        a(f"- {rep['threshold_source']}")
    a("")
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--title", default="fast-v1")
    ap.add_argument("--out-md", required=True)
    args = ap.parse_args()

    card = build_card(Path(args.model), Path(args.report), title=args.title)
    Path(args.out_md).write_text(card, encoding="utf-8")
    rep = json.loads(Path(args.report).read_text())
    print(json.dumps({
        "status": "ok",
        "production_ready": bool(rep.get("production_ready")),
        "card": args.out_md,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
