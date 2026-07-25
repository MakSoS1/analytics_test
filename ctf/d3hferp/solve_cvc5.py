#!/usr/bin/env python3
import os
import re
from pathlib import Path

import cvc5
from cvc5 import Kind

BLOCK = int(os.environ.get("BLOCK", "0"))
BASE = Path(__file__).resolve().parent
PUB = BASE / "D3HFERP" / "pubkey.txt"
CT = BASE / "D3HFERP" / "ciphertext.txt"
OUT = Path(os.environ.get("RESULT_PATH", str(BASE / "result-cvc5.txt")))

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
    assert len(values) == n * (n + 1) // 2
    t = 0
    for i in range(n):
        for j in range(i, n):
            P[k][i][j] = values[t]
            P[k][j][i] = values[t]
            t += 1
    L[k] = list(map(int, lines[pos].split()))
    pos += 1
    C[k] = int(lines[pos])
    pos += 1
assert pos == len(lines)

ct_lines = [line.strip() for line in CT.read_text(encoding="utf-8").splitlines() if line.strip()]
cn, cm, blocks = map(int, ct_lines[0].split())
assert (cn, cm) == (n, m) and 0 <= BLOCK < blocks
target = list(map(int, ct_lines[BLOCK + 1]))
assert len(target) == m

slv = cvc5.Solver()
slv.setLogic("QF_FF")
slv.setOption("produce-models", "true")
F = slv.mkFiniteFieldSort("3")
zero = slv.mkFiniteFieldElem("0", F)
one = slv.mkFiniteFieldElem("1", F)
two = slv.mkFiniteFieldElem("2", F)
const = [zero, one, two]
x = [slv.mkConst(F, f"x{i}") for i in range(n)]

def mul(a, b):
    return slv.mkTerm(Kind.FINITE_FIELD_MULT, a, b)

def add_many(terms):
    if not terms:
        return zero
    if len(terms) == 1:
        return terms[0]
    return slv.mkTerm(Kind.FINITE_FIELD_ADD, *terms)

for k in range(m):
    terms = []
    constant = (C[k] - target[k]) % 3
    if constant:
        terms.append(const[constant])
    for i in range(n):
        if P[k][i][i]:
            sq = mul(x[i], x[i])
            terms.append(sq if P[k][i][i] == 1 else mul(two, sq))
        if L[k][i]:
            terms.append(x[i] if L[k][i] == 1 else mul(two, x[i]))
        for j in range(i + 1, n):
            coefficient = (2 * P[k][i][j]) % 3
            if coefficient:
                product = mul(x[i], x[j])
                terms.append(product if coefficient == 1 else mul(two, product))
    slv.assertFormula(slv.mkTerm(Kind.EQUAL, add_many(terms), zero))

result = slv.checkSat()
if not result.isSat():
    raise RuntimeError(f"cvc5 returned {result}")

def ff_value(term):
    value = slv.getValue(term)
    try:
        return int(value.getFiniteFieldValue()) % 3
    except Exception:
        text = str(value)
        for pattern in (r"#f([0-9]+)m3", r"ff([0-9]+)", r"\b([0-2])\b"):
            match = re.search(pattern, text)
            if match:
                return int(match.group(1)) % 3
        raise RuntimeError(f"Cannot parse finite-field value: {text}")

solution = [ff_value(v) for v in x]

for k in range(m):
    value = C[k]
    for i in range(n):
        value += P[k][i][i] * solution[i] * solution[i]
        value += L[k][i] * solution[i]
        for j in range(i + 1, n):
            value += 2 * P[k][i][j] * solution[i] * solution[j]
    if value % 3 != target[k]:
        raise RuntimeError(f"Model verification failed on equation {k}")

OUT.write_text(
    f"block={BLOCK}\ntrits={''.join(map(str, solution))}\nbackend=cvc5\n",
    encoding="utf-8",
)
print("Verified cvc5 solution saved", flush=True)
