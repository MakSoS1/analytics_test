#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from pysat.formula import CNF
from pysat.solvers import SolverNames
import pysat.solvers as solvers

BASE = Path(__file__).resolve().parent
PUB = BASE / "D3HFERP" / "pubkey.txt"
CT = BASE / "D3HFERP" / "ciphertext.txt"
BLOCK = int(os.environ.get("BLOCK", sys.argv[1] if len(sys.argv) > 1 else "6"))
ZERO_FROM = int(os.environ.get("ZERO_FROM", "16" if BLOCK == 6 else "-1"))
OUT = Path(os.environ.get("RESULT_PATH", str(BASE / f"result-pysat-{BLOCK}.txt")))

lines = [line.strip() for line in PUB.read_text(encoding="utf-8").splitlines() if line.strip()]
q, n, m = map(int, lines[0].split())
assert (q, n, m) == (3, 31, 53)

P = [[[0] * n for _ in range(n)] for _ in range(m)]
L = [[0] * n for _ in range(m)]
C = [0] * m
pos = 1
for k in range(m):
    values = list(map(int, lines[pos].split()))
    pos += 1
    t = 0
    for i in range(n):
        for j in range(i, n):
            P[k][i][j] = values[t] % 3
            P[k][j][i] = values[t] % 3
            t += 1
    L[k] = [v % 3 for v in map(int, lines[pos].split())]
    pos += 1
    C[k] = int(lines[pos]) % 3
    pos += 1
assert pos == len(lines)

ct_lines = [line.strip() for line in CT.read_text(encoding="utf-8").splitlines() if line.strip()]
cn, cm, blocks = map(int, ct_lines[0].split())
assert (cn, cm) == (n, m) and 0 <= BLOCK < blocks
target = list(map(int, ct_lines[BLOCK + 1]))
assert len(target) == m

cnf = CNF()
next_var = 1


def new_trit() -> tuple[int, int, int]:
    global next_var
    values = (next_var, next_var + 1, next_var + 2)
    next_var += 3
    cnf.append(list(values))
    cnf.append([-values[0], -values[1]])
    cnf.append([-values[0], -values[2]])
    cnf.append([-values[1], -values[2]])
    return values


def add_relation(a: tuple[int, int, int], ca: int, b: tuple[int, int, int], cb: int) -> tuple[int, int, int]:
    out = new_trit()
    for va in range(3):
        for vb in range(3):
            cnf.append([-a[va], -b[vb], out[(ca * va + cb * vb) % 3]])
    return out


def mul_relation(a: tuple[int, int, int], b: tuple[int, int, int]) -> tuple[int, int, int]:
    out = new_trit()
    for va in range(3):
        for vb in range(3):
            cnf.append([-a[va], -b[vb], out[(va * vb) % 3]])
    return out


# Create plaintext trits first so decision heuristics can prioritize them.
x = [new_trit() for _ in range(n)]
if ZERO_FROM >= 0:
    for i in range(ZERO_FROM, n):
        cnf.append([x[i][0]])

products: dict[tuple[int, int], tuple[int, int, int]] = {}
for i in range(n):
    for j in range(i, n):
        products[i, j] = mul_relation(x[i], x[j])

for k in range(m):
    terms: list[tuple[tuple[int, int, int], int]] = []
    for i in range(n):
        coeff = P[k][i][i] % 3
        if coeff:
            terms.append((products[i, i], coeff))
        coeff = L[k][i] % 3
        if coeff:
            terms.append((x[i], coeff))
        for j in range(i + 1, n):
            coeff = (2 * P[k][i][j]) % 3
            if coeff:
                terms.append((products[i, j], coeff))

    constant = (C[k] - target[k]) % 3
    if constant:
        const_trit = new_trit()
        cnf.append([const_trit[constant]])
        terms.append((const_trit, 1))

    # Balanced reduction produces shallower implication chains.
    while len(terms) > 1:
        reduced: list[tuple[tuple[int, int, int], int]] = []
        index = 0
        while index < len(terms):
            if index + 1 == len(terms):
                reduced.append(terms[index])
                index += 1
                continue
            (a, ca), (b, cb) = terms[index], terms[index + 1]
            reduced.append((add_relation(a, ca, b, cb), 1))
            index += 2
        terms = reduced

    if terms:
        cnf.append([terms[0][0][0]])
    elif constant:
        raise RuntimeError("constant-only inconsistent equation")

print(
    f"block={BLOCK} vars={next_var - 1} clauses={len(cnf.clauses)} zero_from={ZERO_FROM}",
    flush=True,
)

solver_classes = [
    "Cadical195",
    "Cadical153",
    "Glucose42",
    "Glucose4",
    "Maplesat",
    "Minisat22",
]
solver = None
chosen = None
for class_name in solver_classes:
    cls = getattr(solvers, class_name, None)
    if cls is None:
        continue
    try:
        solver = cls(bootstrap_with=cnf.clauses, use_timer=True)
        chosen = class_name
        break
    except Exception as exc:
        print(f"backend {class_name} unavailable: {type(exc).__name__}: {exc}", flush=True)

if solver is None:
    raise RuntimeError(f"No usable PySAT backend. Available aliases: {SolverNames}")

# Prefer zero for each original trit, while leaving learned activity free to override it.
try:
    solver.set_phases([trit[0] for trit in x])
except Exception:
    pass

started = time.time()
sat = solver.solve()
elapsed = time.time() - started
print(f"backend={chosen} sat={sat} elapsed={elapsed:.3f}", flush=True)
if not sat:
    raise RuntimeError("CNF is unsatisfiable")

model = set(lit for lit in solver.get_model() if lit > 0)
solution = []
for trit in x:
    values = [value for value, variable in enumerate(trit) if variable in model]
    if len(values) != 1:
        raise RuntimeError(f"invalid one-hot model: {trit} -> {values}")
    solution.append(values[0])

for k in range(m):
    value = C[k]
    for i in range(n):
        value += P[k][i][i] * solution[i] * solution[i]
        value += L[k][i] * solution[i]
        for j in range(i + 1, n):
            value += 2 * P[k][i][j] * solution[i] * solution[j]
    if value % 3 != target[k]:
        raise RuntimeError(f"verification failed on equation {k}")

OUT.write_text(
    f"block={BLOCK}\n"
    f"trits={''.join(map(str, solution))}\n"
    f"backend={chosen}\n"
    f"elapsed={elapsed:.6f}\n",
    encoding="utf-8",
)
print("verified trits=" + "".join(map(str, solution)), flush=True)
solver.delete()
