#!/usr/bin/env python3
"""Build the demo notebook: two capture files in, the model's real answer out.

The 68 per-family notebooks read a pre-computed evidence summary, which is the
right shape for analysis and the wrong shape for showing someone how the
detector works — nothing in them touches a packet. This one starts from two
pcap files and runs the shipped path over them: `score_pcap.observe_flows` for
the features and the route's own model for the verdict. What it prints is
whatever the model said; it is never told which file is which.

The cell sources are held verbatim so that what ships is exactly what was run
and checked, with only the three names below substituted.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

DEFAULT_ANALYSIS_ROOT = "/home/jovyan/work/full68"
DEFAULT_TUNNEL_PCAP = "tunnel_vless_reality_xtls.pcap"
DEFAULT_BENIGN_PCAP = "benign_https_browse.pcap"

# (cell type, source). The first code cell opens with the three names, so the
# rest of the notebook refers to them and nothing else needs substituting.
_CELLS: list[tuple[str, str]] = [
    ('markdown', '# Демонстрация детектора туннелей\n\nНа входе — два файла захвата. В одном туннель, в другом обычный трафик.\nНоутбук сам достаёт из них признаки и прогоняет через обученную модель;\nничего заранее посчитанного он не читает, разметку файлов модель не видит.\n\n**Как это работает:** пакеты → потоки (первые 20 пакетов или 5 секунд) →\nмаршрут по транспорту → модель этого маршрута → оценка против порога.'),
    ('code', '__PREAMBLE__import os, sys, time\nfrom pathlib import Path\n\nROOT = Path(ANALYSIS_ROOT)\nsys.path.insert(0, str(ROOT))\nos.environ["MPLBACKEND"] = "Agg"\n\nimport io\nimport matplotlib\nmatplotlib.use("Agg")\nimport matplotlib.pyplot as plt\nfrom IPython.display import Markdown, Image as IPImage, display\n\nplt.rcParams.update({"font.size": 9, "axes.grid": True, "grid.alpha": 0.25})\n\nfrom lab_pipeline.score_pcap import load_route_models, observe_flows, score_flows\n\nDEMO = ROOT / "demo"\nFILES = {\n    "туннель": DEMO / TUNNEL_PCAP,\n    "обычный": DEMO / BENIGN_PCAP,\n}\nMODELS = load_route_models(ROOT / "models_router")\n\n\ndef note(text):\n    display(Markdown(text))\n\n\ndef show(figure):\n    buffer = io.BytesIO()\n    figure.savefig(buffer, format="png", dpi=115, bbox_inches="tight")\n    plt.close(figure)\n    display(IPImage(data=buffer.getvalue()))\n\n\nnote("Загружены модели маршрутов: " + ", ".join(\n    f"`{r}` (порог {m.threshold:.3f})" for r, m in sorted(MODELS.items())))\nfor label, path in FILES.items():\n    note(f"**{label}**: `{path.name}`, {path.stat().st_size / 1024:.0f} КБ")'),
    ('markdown', '## 1. Что модель сказала\n\nКаждый файл разбирается на потоки, каждый поток получает свою оценку.'),
    ('code', 'RESULTS = {}\nfor label, path in FILES.items():\n    started = time.time()\n    flows = observe_flows(path)\n    scored = score_flows(flows, MODELS)\n    RESULTS[label] = {"scored": scored, "seconds": time.time() - started}\n\nlines = ["| файл | потоков | признан туннелем | максимальная оценка | время разбора |",\n         "|---|---|---|---|---|"]\nfor label, data in RESULTS.items():\n    scored = data["scored"]\n    hits = sum(1 for s in scored if s["tunnel_detected"])\n    top = max((s["score"] for s in scored), default=0.0)\n    lines.append(f"| {label} | {len(scored)} | **{hits}** | {top:.3f} | {data[\'seconds\'] * 1000:.0f} мс |")\nnote("\\n".join(lines))\n\nverdict = []\nfor label, data in RESULTS.items():\n    hits = sum(1 for s in data["scored"] if s["tunnel_detected"])\n    verdict.append(f"**{label}** — " + ("туннель обнаружен" if hits else "туннеля нет"))\nnote("### Вывод модели\\n\\n" + "\\n\\n".join(verdict))'),
    ('markdown', '## 2. Оценка каждого потока\n\nТочка — один поток. Красным — те, что модель признала туннелем; пунктир — порог.'),
    ('code', 'figure, axes = plt.subplots(figsize=(7.6, 3.4))\noffsets = {"туннель": 1, "обычный": 0}\nthreshold = MODELS["tcp_tls_fast"].threshold\nfor label, data in RESULTS.items():\n    y = offsets[label]\n    scores = [s["score"] for s in data["scored"]]\n    colors = ["#c0392b" if s["tunnel_detected"] else "#2c3e50" for s in data["scored"]]\n    axes.scatter(scores, [y + 0.06 * ((i % 7) - 3) for i in range(len(scores))],\n                 c=colors, s=26, alpha=0.85)\naxes.axvline(threshold, color="#e67e22", ls="--", lw=1.4)\naxes.text(threshold, 1.42, f" порог {threshold:.3f}", color="#e67e22", fontsize=8, va="top")\naxes.set_yticks([0, 1]); axes.set_yticklabels(["обычный", "туннель"])\naxes.set_xlim(-0.03, 1.03); axes.set_ylim(-0.5, 1.5)\naxes.set_xlabel("оценка модели: вероятность того, что поток туннельный")\naxes.set_title("Оценка каждого потока в обоих файлах")\nshow(figure)'),
    ('markdown', '## 3. Почему модель так решила\n\nБерём самый уверенный туннельный поток и самый обычный и сравниваем их\nпо тем признакам, на которые модель опирается сильнее всего.'),
    ('code', 'import json as _json\n\nreport = _json.loads((ROOT / "models_router" / "tcp_tls_fast_report.json").read_text())\nweights = {e["name"]: e["importance"] for e in report["feature_importances"]}\ntop_names = [n for n, _ in sorted(weights.items(), key=lambda kv: -kv[1])[:8]]\n\nbest_tunnel = max(RESULTS["туннель"]["scored"], key=lambda s: s["score"])\nbest_benign = min(RESULTS["обычный"]["scored"], key=lambda s: s["score"])\n\nMEANING = {\n    "iat_mean": "средняя пауза между пакетами",\n    "iat_std": "насколько неровны паузы",\n    "pkt_len_mean": "средний размер пакета",\n    "pkt_len_std": "насколько разнородны размеры",\n    "up_down_bytes_ratio": "перекос по объёму между сторонами",\n    "up_down_pkt_ratio": "перекос по числу пакетов",\n    "direction_changes": "как часто менялось направление",\n    "total_bytes": "объём за окно",\n    "up_bytes": "байт вверх", "down_bytes": "байт вниз",\n    "observed_duration": "длительность окна",\n}\n\n\ndef explain(name):\n    if name in MEANING:\n        return MEANING[name]\n    if name.startswith("signed_len_"):\n        return f"размер {int(name.rsplit(\'_\', 1)[1]) + 1}-го пакета, знак — направление"\n    if name.startswith("iat_"):\n        return f"пауза перед {int(name.rsplit(\'_\', 1)[1]) + 1}-м пакетом"\n    if name.startswith("dir_"):\n        return f"куда шёл {int(name.rsplit(\'_\', 1)[1]) + 1}-й пакет"\n    if name.startswith("mask_"):\n        return f"дошло ли дело до {int(name.rsplit(\'_\', 1)[1]) + 1}-го пакета"\n    return name\n\n\nfigure, axes = plt.subplots(figsize=(7.6, 0.5 * len(top_names) + 1.2))\nrows = top_names[::-1]\nfor index, name in enumerate(rows):\n    a = best_tunnel["flow"].features[name]\n    b = best_benign["flow"].features[name]\n    span = max(abs(a), abs(b)) or 1.0\n    axes.barh(index + 0.18, a / span, height=0.34, color="#c0392b")\n    axes.barh(index - 0.18, b / span, height=0.34, color="#2c3e50")\n    axes.text(1.02, index, f"{a:.4g} / {b:.4g}", fontsize=8, va="center", color="#555")\naxes.set_yticks(range(len(rows)))\naxes.set_yticklabels([f"{n}\\n{explain(n)}" for n in rows], fontsize=8)\naxes.set_xlabel("значение признака в долях от большего из двух")\naxes.set_title("Туннельный поток (красный) против обычного (тёмный)")\nshow(figure)\n\nnote(f"Оценка сравниваемых потоков: туннельный **{best_tunnel[\'score\']:.3f}**, "\n     f"обычный **{best_benign[\'score\']:.3f}** при пороге **{best_tunnel[\'threshold\']:.3f}**.")'),
    ('markdown', '## 4. Что модель видела на самом деле\n\nНи адресов, ни портов, ни имени семейства в модель не попадает — только\nпризнаки формы трафика. Ниже то, что реально пришло на вход по одному потоку.'),
    ('code', 'sample = best_tunnel["flow"]\nshown = {k: round(v, 6) for k, v in list(sample.features.items())[:10]}\nnote("**Маршрут потока:** `" + sample.route + "` — выбран по транспорту, "\n     "имя семейства модели не сообщается.\\n\\n"\n     "**Первые 10 признаков из " + str(len(sample.features)) + ":**\\n\\n```\\n"\n     + "\\n".join(f"{k:22} {v}" for k, v in shown.items()) + "\\n```")\nnote(f"**Идентификатор модели:** `{best_tunnel[\'model_id\']}` — "\n     "SHA-256 файла модели, по нему видно, какие именно веса отработали.")'),
]


def build_demo_notebook(out_path: Path, *, analysis_root: str = DEFAULT_ANALYSIS_ROOT,
                        tunnel_pcap: str = DEFAULT_TUNNEL_PCAP,
                        benign_pcap: str = DEFAULT_BENIGN_PCAP) -> Path:
    """Write the demo notebook next to the two captures it reads."""
    preamble = (f"ANALYSIS_ROOT = {analysis_root!r}\n"
                f"TUNNEL_PCAP = {tunnel_pcap!r}\n"
                f"BENIGN_PCAP = {benign_pcap!r}\n\n")
    cells = []
    for kind, source in _CELLS:
        source = source.replace("__PREAMBLE__", preamble)
        cell = {"cell_type": kind, "metadata": {},
                "source": [line + "\n" for line in source.split("\n")]}
        if kind == "code":
            cell["execution_count"] = None
            cell["outputs"] = []
        cells.append(cell)
    notebook = {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3"},
            "full68_demo": {"tunnel_pcap": tunnel_pcap, "benign_pcap": benign_pcap,
                            "analysis_root": analysis_root,
                            "generator": "lab_pipeline.generate_demo_notebook"},
        },
        "nbformat": 4, "nbformat_minor": 5,
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(notebook, indent=2, ensure_ascii=False) + "\n")
    return out_path


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--analysis-root", default=DEFAULT_ANALYSIS_ROOT)
    parser.add_argument("--tunnel-pcap", default=DEFAULT_TUNNEL_PCAP)
    parser.add_argument("--benign-pcap", default=DEFAULT_BENIGN_PCAP)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    written = build_demo_notebook(args.out, analysis_root=args.analysis_root,
                                  tunnel_pcap=args.tunnel_pcap, benign_pcap=args.benign_pcap)
    print(json.dumps({"notebook": str(written)}))
