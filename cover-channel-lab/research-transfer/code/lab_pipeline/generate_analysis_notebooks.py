"""Generate one individual analysis notebook per canonical full68 family.

Not a template with the name swapped. Each notebook embeds that family's own
curated wire profile — what the protocol does, and which fast-v1 features that
mechanism should move — and then checks the prediction against the measurement
and against what the trained route model actually weighs. A family whose
prediction misses says so; that is the point of writing the prediction first.

The generator is portable source code. Generated notebooks are written only
beneath a caller-supplied WSL root and read their evidence from an environment
variable at execution time, so no traffic material is embedded here.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from lab_pipeline.analysis_units import load_analysis_units, validate_analysis_units
from lab_pipeline.capture_blockers import load_blockers
from lab_pipeline.family_profiles import load_family_profiles
from lab_pipeline.full_scope import load_full_scope


DEFAULT_WSL_ROOT = Path("/opt/tunnel_lab")


def generate_analysis_notebooks(
    out_dir: Path,
    *,
    wsl_root: Path = DEFAULT_WSL_ROOT,
    units_contract: dict | None = None,
    scope: dict | None = None,
) -> list[Path]:
    """Write one Notebook v4 file per canonical full68 family."""
    out_dir = out_dir.resolve()
    wsl_root = wsl_root.resolve()
    try:
        out_dir.relative_to(wsl_root)
    except ValueError as exc:
        raise ValueError("analysis notebooks must be generated under the declared WSL root") from exc
    contract = load_analysis_units() if units_contract is None else units_contract
    validate_analysis_units(contract)
    checked_scope = load_full_scope() if scope is None else scope
    profiles = load_family_profiles(scope=checked_scope)
    blockers = load_blockers(scope=checked_scope)
    route_by_family = {row["family"]: row["route"] for row in checked_scope["families"]}

    unit_by_family: dict[str, dict] = {}
    for unit in contract["units"]:
        for family in unit["families"]:
            unit_by_family[family] = unit

    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for family in sorted(profiles):
        notebook = _notebook_for_family(
            family,
            route=route_by_family[family],
            unit=unit_by_family[family],
            profile=profiles[family],
            blocker=blockers.get(family),
        )
        path = out_dir / f"{family}.ipynb"
        path.write_text(json.dumps(notebook, indent=2, ensure_ascii=False) + "\n")
        paths.append(path)
    return paths


def _notebook_for_family(
    family: str, *, route: str, unit: dict, profile: dict, blocker: dict | None,
) -> dict:
    siblings = [name for name in unit["families"] if name != family]
    cells = [
        _markdown_cell(_intro(family, route, siblings, profile, blocker)),
        _setup_cell(family, profile),
        _markdown_cell(
            "## 1. Чем этот туннель выдаёт себя\n\n"
            "Только признаки, которые реально разошлись с обычным трафиком. "
            "Красным — те, которые использует и обученная модель."
        ),
        _code_cell("chart_separation()"),
        _markdown_cell(
            "## 2. Почему сработали именно эти признаки\n\n"
            "Что каждый из них меряет на проводе и откуда берётся разница именно у "
            "этого протокола."
        ),
        _code_cell("why()"),
        _markdown_cell(
            "## 3. Туннель против обычного трафика\n\n"
            "Те же признаки в своём масштабе: полоса — разброс p05…p95, точка — медиана."
        ),
        _code_cell("chart_tunnel_vs_benign()"),
        _markdown_cell(
            "## 4. На что смотрит модель\n\n"
            "Вес признака в модели маршрута, который оценивает это семейство."
        ),
        _code_cell("chart_model()"),
    ]
    return {
        "cells": cells,
        "metadata": {
            "kernelspec": {"display_name": "Python 3", "language": "python", "name": "python3"},
            "language_info": {"name": "python", "version": "3"},
            "full68_analysis": {
                "family": family,
                "route": route,
                "unit_id": unit["unit_id"],
                "unit_families": unit["families"],
                "evidence_mode": unit["evidence_mode"],
                "predicted_features": [p["feature"] for p in profile["expected_features"]],
                "confusable_with": profile["confusable_with"],
                "capture_blocked": bool(blocker),
                "generator": "lab_pipeline.generate_analysis_notebooks",
            },
        },
        "nbformat": 4,
        "nbformat_minor": 5,
    }


_BLOCKER_RU = {
    "upstream_removed": "исходники проекта удалены из upstream",
    "vendor_issued_config_required": "клиенту нужен конфиг от вендора",
    "no_headless_control_path": "нет способа управлять клиентом без графического интерфейса",
    "no_server_implementation": "серверной реализации не существует",
}


def _intro(family: str, route: str, siblings: list[str], profile: dict, blocker: dict | None) -> str:
    confusable = profile["confusable_with"]
    lines = [f"# `{family}`", "", profile["ru_summary"], ""]
    if blocker:
        lines += [
            f"> **Трафик этого семейства снять нельзя:** {_BLOCKER_RU.get(blocker['reason'], blocker['reason'])}. "
            "Ниже поэтому не будет ни графиков, ни метрик — это верный результат, а не сбой.",
            "",
        ]
    lines.append(f"**Маршрут детекции:** `{route}`")
    if confusable:
        lines.append("**Труднее всего отличить от:** " + ", ".join(f"`{n}`" for n in confusable))
    lines += [
        "",
        "Ноутбук только читает готовую агрегированную сводку: ни pcap, ни адресов, ни "
        "идентификаторов сессий в нём нет. Поведение на офисном трафике — отдельный этап.",
    ]
    return "\n".join(lines)


def _setup_cell(family: str, profile: dict) -> dict:
    predicted = [entry["feature"] for entry in profile["expected_features"]]
    source = f'''import json
import os
from pathlib import Path

from IPython.display import Markdown, display

FAMILY = {family!r}
PREDICTED = {json.dumps(predicted, ensure_ascii=False)}
CONFUSABLE = {json.dumps(profile["confusable_with"], ensure_ascii=False)}
# Природа самого протокола: откуда у него вообще берётся наблюдаемая разница.
RU_WHY = {json.dumps(profile["ru_why"], ensure_ascii=False)}

# Полностью разделённый признак: разброс нулевой, а средние разные. Настоящей
# величины у такой разницы нет, поэтому в сводке стоит метка-заглушка.
SEPARATED = 1e6
# Ниже этого признак считаем шумом и на график не выносим.
MIN_EFFECT = 0.2
TOP_N = 8

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import io
from IPython.display import Image as IPImage

plt.rcParams.update({{"font.size": 9, "axes.grid": True, "grid.alpha": 0.25}})

from lab_pipeline.analysis_evidence import family_analysis_summary, load_analysis_evidence
from lab_pipeline.full_scope import load_full_scope

scope = load_full_scope()
_path = os.environ.get("FULL68_ANALYSIS_EVIDENCE_JSON")
evidence = load_analysis_evidence(Path(_path), scope) if _path else None
summary = (family_analysis_summary(FAMILY, evidence, scope) if evidence else
           {{"family": FAMILY, "analysis_state": "blocked", "blocking_reasons": ["нет сводки"],
             "lab_capture": None, "feature_summary": None, "benign_feature_summary": None,
             "discriminative_features": None, "model_feature_importances": None,
             "held_out_metrics": None, "public_source": None}})

MODEL = {{e["name"]: e["importance"] for e in (summary.get("model_feature_importances") or [])}}


def note(text):
    display(Markdown(text))


def show(figure):
    # PNG кодируется явно: если отдать объект Figure прямо в display, картинка
    # появится только при зарегистрированном inline-бэкенде, которого в обычном
    # ядре нет — там раздел молча оставался пустым.
    buffer = io.BytesIO()
    figure.savefig(buffer, format="png", dpi=115, bbox_inches="tight")
    plt.close(figure)
    display(IPImage(data=buffer.getvalue()))


def working_features():
    """Признаки, которые действительно разошлись у ЭТОГО семейства."""
    ranked = summary.get("discriminative_features") or []
    kept = [e for e in ranked if e["effect_size"] >= MIN_EFFECT]
    return kept[:TOP_N]


def chart_separation():
    rows = working_features()
    if not rows:
        note("Разошедшихся признаков нет: для этого семейства не с чем сравнивать — "
             "нет парного обычного трафика или нет принятых сессий.")
        return
    names = [e["name"] for e in rows][::-1]
    finite = [e["effect_size"] for e in rows if e["effect_size"] < SEPARATED]
    ceiling = (max(finite) * 1.25) if finite else 1.0
    values = [min(e["effect_size"], ceiling) for e in rows][::-1]
    full = [e["effect_size"] >= SEPARATED for e in rows][::-1]
    colors = ["#c0392b" if n in MODEL else "#7f8c8d" for n in names]

    figure, axes = plt.subplots(figsize=(7.2, max(2.2, 0.42 * len(names))))
    bars = axes.barh(names, values, color=colors)
    for bar, is_full in zip(bars, full):
        if is_full:
            axes.text(bar.get_width(), bar.get_y() + bar.get_height() / 2,
                      "  разделены полностью", va="center", fontsize=8, color="#c0392b")
    axes.set_xlabel("во сколько σ туннель отличается от обычного трафика")
    axes.set_title(f"{{FAMILY}}: по чему отличается")
    show(figure)



def chart_tunnel_vs_benign():
    rows = working_features()
    tunnel = summary.get("feature_summary")
    benign = summary.get("benign_feature_summary")
    if not rows or not tunnel or not benign:
        note("Нет парного обычного трафика — сравнивать не с чем.")
        return
    t_by = {{f["name"]: f for f in tunnel["features"]}}
    b_by = {{f["name"]: f for f in benign["features"]}}

    names, t_pos, b_pos, t_span, b_span, labels = [], [], [], [], [], []
    for entry in rows:
        name = entry["name"]
        a, b = t_by.get(name), b_by.get(name)
        if not a or not b:
            continue
        lo = min(a["p05"], b["p05"])
        hi = max(a["p95"], b["p95"])
        width = (hi - lo) or 1.0
        scale = lambda v: (v - lo) / width
        names.append(name)
        t_pos.append(scale(a["p50"])); b_pos.append(scale(b["p50"]))
        t_span.append((scale(a["p05"]), scale(a["p95"])))
        b_span.append((scale(b["p05"]), scale(b["p95"])))
        labels.append(f"{{a['p50']:.4g}} / {{b['p50']:.4g}}")
    if not names:
        note("Нет общих признаков для сравнения.")
        return

    figure, axes = plt.subplots(figsize=(7.2, max(2.2, 0.5 * len(names))))
    for index, name in enumerate(names):
        y = len(names) - 1 - index
        axes.plot(t_span[index], [y + 0.12] * 2, color="#c0392b", lw=5, alpha=0.35,
                  solid_capstyle="butt")
        axes.plot(b_span[index], [y - 0.12] * 2, color="#2c3e50", lw=5, alpha=0.35,
                  solid_capstyle="butt")
        axes.plot(t_pos[index], y + 0.12, "o", color="#c0392b", ms=6)
        axes.plot(b_pos[index], y - 0.12, "o", color="#2c3e50", ms=6)
        axes.text(1.02, y, labels[index], va="center", fontsize=8, color="#555")
    axes.set_yticks(range(len(names)))
    axes.set_yticklabels(names[::-1])
    axes.set_xlim(-0.05, 1.05)
    axes.set_xlabel("масштаб признака: от p05 до p95 по обеим группам")
    axes.set_title(f"{{FAMILY}}: туннель (красный) против обычного трафика (тёмный)")
    axes.text(1.02, len(names) - 0.5, "медианы", fontsize=8, color="#555")
    show(figure)


def chart_model():
    ranked = summary.get("model_feature_importances") or []
    if not ranked:
        note("Модель маршрута к этой сводке не привязана — что она использует, сказать нечем.")
        return
    top = ranked[:12]
    names = [e["name"] for e in top][::-1]
    values = [e["importance"] for e in top][::-1]
    worked = {{e["name"] for e in working_features()}}
    colors = ["#c0392b" if n in worked else "#7f8c8d" for n in names]
    figure, axes = plt.subplots(figsize=(7.2, max(2.2, 0.36 * len(names))))
    axes.barh(names, values, color=colors)
    axes.set_xlabel("вес признака в модели")
    axes.set_title(f"{{FAMILY}}: что взвешивает модель (красным — то, что и разошлось)")
    show(figure)
    overlap = sorted(worked & set(MODEL))
    note("Совпало с разошедшимися признаками: "
         + ("`" + "`, `".join(overlap) + "`." if overlap else
            "ничего — модель нашла другой путь к тому же решению."))


import re as _re

# Что признак физически меряет на проводе. Нужно, чтобы список сработавших
# читался без знания контракта фич.
_MEANING = {{
    "pkt_count": "сколько всего пакетов прошло за окно",
    "up_pkt_count": "сколько пакетов отправил клиент",
    "down_pkt_count": "сколько пакетов прислал сервер",
    "total_bytes": "сколько всего байт прошло за окно",
    "up_bytes": "сколько байт ушло вверх",
    "down_bytes": "сколько байт пришло вниз",
    "observed_duration": "сколько времени заняло наблюдаемое окно",
    "flow_duration": "сколько времени заняло наблюдаемое окно",
    "up_down_pkt_ratio": "перекос по числу пакетов между сторонами",
    "up_down_bytes_ratio": "перекос по объёму между сторонами",
    "pkt_rate": "сколько пакетов в секунду",
    "byte_rate": "сколько байт в секунду",
    "pkt_len_mean": "средний размер пакета",
    "mean_pkt_size": "средний размер пакета",
    "up_mean_pkt_size": "средний размер пакета вверх",
    "down_mean_pkt_size": "средний размер пакета вниз",
    "pkt_len_std": "насколько разнородны размеры пакетов",
    "pkt_len_min": "размер самого мелкого пакета",
    "pkt_len_max": "размер самого крупного пакета",
    "iat_mean": "средняя пауза между пакетами",
    "iat_std": "насколько неровно распределены паузы",
    "iat_min": "самая короткая пауза",
    "iat_max": "самая длинная пауза",
    "direction_changes": "сколько раз инициатива переходила от одной стороны к другой",
    "is_udp": "признак UDP-транспорта",
    "is_tcp": "признак TCP-транспорта",
    "syn_count": "сколько раз соединение пытались открыть",
    "fin_count": "сколько раз соединение закрыли штатно",
    "rst_count": "сколько раз соединение оборвали",
}}
_INDEXED = {{
    "signed_len": "размер {{n}}-го пакета, знак — направление",
    "dir": "куда шёл {{n}}-й пакет",
    "iat": "пауза перед {{n}}-м пакетом",
    "mask": "дошло ли дело до {{n}}-го пакета вообще",
}}


def _meaning(name):
    if name in _MEANING:
        return _MEANING[name]
    match = _re.match(r"^(.*)_(\\d+)$", name)
    if match and match.group(1) in _INDEXED:
        return _INDEXED[match.group(1)].format(n=int(match.group(2)) + 1)
    return "значение из контракта fast-v1"


def why():
    rows = working_features()
    if not rows:
        note("Разбирать нечего: ни один признак у этого семейства пока не разошёлся.\\n\\n" + RU_WHY)
        return
    tunnel = {{f["name"]: f for f in (summary.get("feature_summary") or {{"features": []}})["features"]}}
    benign = {{f["name"]: f for f in (summary.get("benign_feature_summary") or {{"features": []}})["features"]}}

    lines = []
    for entry in rows:
        name = entry["name"]
        a, b = tunnel.get(name), benign.get(name)
        if a and b and a["p50"] != b["p50"]:
            side = "выше" if a["p50"] > b["p50"] else "ниже"
            where = f"; у туннеля {{side}} ({{a['p50']:.4g}} против {{b['p50']:.4g}})"
        elif a and b:
            where = "; медианы совпали, расходится разброс"
        else:
            where = ""
        tail = " *Ожидалось по устройству протокола.*" if name in PREDICTED else ""
        lines.append(f"- **`{{name}}`** — {{_meaning(name)}}{{where}}.{{tail}}")
    note("\\n".join(lines))
    note("**Как это связано с самим туннелем.** " + RU_WHY)


'''
    return _code_cell(source)


def _markdown_cell(source: str) -> dict:
    return {"cell_type": "markdown", "metadata": {}, "source": _lines(source)}


def _code_cell(source: str) -> dict:
    return {
        "cell_type": "code",
        "execution_count": None,
        "metadata": {},
        "outputs": [],
        "source": _lines(source),
    }


def _lines(source: str) -> list[str]:
    return [line + "\n" for line in source.rstrip("\n").split("\n")]


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", required=True, type=Path)
    parser.add_argument("--wsl-root", type=Path, default=DEFAULT_WSL_ROOT)
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    result = generate_analysis_notebooks(args.out_dir, wsl_root=args.wsl_root)
    print(json.dumps({"notebooks": len(result), "out_dir": str(args.out_dir)}))
