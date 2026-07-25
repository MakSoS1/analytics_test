from sage.all import *
import os
import sys
import time

BLOCK = int(os.environ.get("BLOCK", sys.argv[1] if len(sys.argv) > 1 else 0))
BASE = os.path.dirname(os.path.abspath(__file__))
PUB = os.path.join(BASE, "D3HFERP", "pubkey.txt")
CT = os.path.join(BASE, "D3HFERP", "ciphertext.txt")
OUT = os.environ.get("RESULT_PATH", os.path.join(BASE, "result.txt"))

F = GF(3)

with open(PUB, "r", encoding="utf-8") as fh:
    lines = [line.strip() for line in fh if line.strip()]
q, n, m = map(int, lines[0].split())
assert q == 3 and n == 31 and m == 53

P = []
L = []
C = []
pos = 1
for k in range(m):
    values = list(map(int, lines[pos].split()))
    pos += 1
    assert len(values) == n * (n + 1) // 2
    M = matrix(F, n, n)
    t = 0
    for i in range(n):
        for j in range(i, n):
            M[i, j] = F(values[t])
            M[j, i] = F(values[t])
            t += 1
    P.append(M)
    lv = list(map(int, lines[pos].split()))
    pos += 1
    assert len(lv) == n
    L.append(vector(F, lv))
    C.append(F(int(lines[pos])))
    pos += 1
assert pos == len(lines)

with open(CT, "r", encoding="utf-8") as fh:
    ct_lines = [line.strip() for line in fh if line.strip()]
cn, cm, blocks = map(int, ct_lines[0].split())
assert cn == n and cm == m and 0 <= BLOCK < blocks
target = [F(int(ch)) for ch in ct_lines[BLOCK + 1]]
assert len(target) == m

names = [f"x{i}" for i in range(n)]
R = PolynomialRing(F, names=names, order="degrevlex")
x = R.gens()

polys = []
for k in range(m):
    f = R(C[k] - target[k])
    for i in range(n):
        if P[k][i, i]:
            f += R(P[k][i, i]) * x[i]**2
        if L[k][i]:
            f += R(L[k][i]) * x[i]
        for j in range(i + 1, n):
            coeff = F(2) * P[k][i, j]
            if coeff:
                f += R(coeff) * x[i] * x[j]
    polys.append(f)

polys.extend(xi**3 - xi for xi in x)
I = R.ideal(polys)

print(f"Solving block {BLOCK}: {len(polys)} equations in {n} variables", flush=True)
started = time.time()
try:
    G = I.groebner_basis(algorithm="slimgb")
except Exception:
    G = I.groebner_basis()

elapsed = time.time() - started
print(f"Groebner basis finished in {elapsed:.1f}s with {len(G)} elements", flush=True)

solution = [None] * n
for g in G:
    if g.total_degree() != 1:
        continue
    nz = [i for i in range(n) if g.monomial_coefficient(x[i]) != 0]
    if len(nz) != 1:
        continue
    i = nz[0]
    a = F(g.monomial_coefficient(x[i]))
    const = F(g.constant_coefficient())
    solution[i] = int(-const / a)

if any(v is None for v in solution):
    sols = I.variety(ring=F)
    if len(sols) != 1:
        raise RuntimeError(f"Expected one solution, got {len(sols)}")
    sol = sols[0]
    solution = [int(sol[xi]) for xi in x]

vx = vector(F, solution)
check = []
for k in range(m):
    check.append(vx * P[k] * vx + L[k] * vx + C[k])
assert vector(F, check) == vector(F, target)

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(f"block={BLOCK}\n")
    fh.write("trits=" + "".join(map(str, solution)) + "\n")
    fh.write(f"elapsed={elapsed:.3f}\n")
print("Verified solution saved", flush=True)
