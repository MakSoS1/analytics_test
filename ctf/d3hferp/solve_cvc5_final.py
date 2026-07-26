#!/usr/bin/env python3
from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

import cvc5
from cvc5 import Kind

BASE = Path(__file__).resolve().parent
PUB = BASE / "D3HFERP" / "pubkey.txt"
CT = BASE / "D3HFERP" / "ciphertext.txt"
BLOCK = int(os.environ.get("BLOCK", sys.argv[1] if len(sys.argv) > 1 else "6"))
ZERO_FROM = int(os.environ.get("ZERO_FROM", "16" if BLOCK == 6 else "-1"))
OUT = Path(os.environ.get("RESULT_PATH", str(BASE / f"result-cvc5-{BLOCK}.txt")))

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

ct_lines = [line.strip() for line in CT.read_text(encoding="utf-8").splitlines() if line.strip()]
cn, cm, blocks = map(int, ct_lines[0].split())
assert (cn, cm) == (n, m) and 0 <= BLOCK < blocks
target = list(map(int, ct_lines[BLOCK + 1]))

slv = cvc5.Solver()
slv.setLogic("QF_FF")
slv.setOption("produce-models", "true")
slv.setOption("tlimit-per", os.environ.get("TIME_LIMIT_MS", "1200000"))
F = slv.mkFiniteFieldSort("3")
const = [slv.mkFiniteFieldElem(str(i), F) for i in range(3)]
x = [slv.mkConst(F, f"x{i}") for i in range(n)]


def mul(a, b):
    return slv.mkTerm(Kind.FINITE_FIELD_MULT, a, b)


def add_many(terms):
    if not terms:
        return const[0]
    if len(terms) == 1:
        return terms[0]
    # Balanced sums avoid one very deep term.
    terms = list(terms)
    while len(terms) > 1:
        nxt = []
        for i in range(0, len(terms), 2):
            if i + 1 == len(terms):
                nxt.append(terms[i])
            else:
                nxt.append(slv.mkTerm(Kind.FINITE_FIELD_ADD, terms[i], terms[i + 1]))
        terms = nxt
    return terms[0]


products = {(i, j): mul(x[i], x[j]) for i in range(n) for j in range(i, n)}
for k in range(m):
    terms = []
    constant = (C[k] - target[k]) % 3
    if constant:
        terms.append(const[constant])
    for i in range(n):
        coeff = P[k][i][i] % 3
        if coeff:
            term = products[i, i]
            terms.append(term if coeff == 1 else mul(const[2], term))
        coeff = L[k][i] % 3
        if coeff:
            terms.append(x[i] if coeff == 1 else mul(const[2], x[i]))
        for j in range(i + 1, n):
            coeff = (2 * P[k][i][j]) % 3
            if coeff:
                term = products[i, j]
                terms.append(term if coeff == 1 else mul(const[2], term))
    slv.assertFormula(slv.mkTerm(Kind.EQUAL, add_many(terms), const[0]))

if ZERO_FROM >= 0:
    for i in range(ZERO_FROM, n):
        slv.assertFormula(slv.mkTerm(Kind.EQUAL, x[i], const[0]))

print(f"block={BLOCK} equations={m} variables={n} zero_from={ZERO_FROM}", flush=True)
started = time.time()
result = slv.checkSat()
elapsed = time.time() - started
print(f"result={result} elapsed={elapsed:.3f}", flush=True)
if not result.isSat():
    raise RuntimeError(f"cvc5 returned {result}")


def parse_value(term) -> int:
    value = slv.getValue(term)
    try:
        return int(value.getFiniteFieldValue()) % 3
    except Exception:
        text = str(value)
        for pattern in (r"#f([0-9]+)m3", r"ff([0-9]+)", r"\b([0-2])\b"):
            match = re.search(pattern, text)
            if match:
                return int(match.group(1)) % 3
        raise RuntimeError(f"cannot parse finite-field value {text!r}")


solution = [parse_value(variable) for variable in x]
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
    f"backend=cvc5\n"
    f"elapsed={elapsed:.6f}\n",
    encoding="utf-8",
)
print("verified trits=" + "".join(map(str, solution)), flush=True)
