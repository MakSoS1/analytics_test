from sage.all import *
import os
import sys
import time

BLOCK = int(os.environ.get("BLOCK", sys.argv[1] if len(sys.argv) > 1 else 6))
ACTIVE_N = int(os.environ.get("ACTIVE_N", "16" if BLOCK == 6 else "31"))
BASE = os.path.dirname(os.path.abspath(__file__))
PUB = os.path.join(BASE, "D3HFERP", "pubkey.txt")
CT = os.path.join(BASE, "D3HFERP", "ciphertext.txt")
OUT = os.environ.get("RESULT_PATH", os.path.join(BASE, f"result-msolve-{BLOCK}.txt"))

F = GF(3)
with open(PUB, "r", encoding="utf-8") as fh:
    lines = [line.strip() for line in fh if line.strip()]
q, n, m = map(int, lines[0].split())
assert (q, n, m) == (3, 31, 53)

P = []
L = []
C = []
pos = 1
for k in range(m):
    values = list(map(int, lines[pos].split()))
    pos += 1
    M = matrix(F, n, n)
    t = 0
    for i in range(n):
        for j in range(i, n):
            M[i, j] = F(values[t])
            M[j, i] = F(values[t])
            t += 1
    P.append(M)
    L.append(vector(F, map(int, lines[pos].split())))
    pos += 1
    C.append(F(int(lines[pos])))
    pos += 1

with open(CT, "r", encoding="utf-8") as fh:
    ct_lines = [line.strip() for line in fh if line.strip()]
cn, cm, blocks = map(int, ct_lines[0].split())
assert (cn, cm) == (n, m) and 0 <= BLOCK < blocks
target = [F(int(ch)) for ch in ct_lines[BLOCK + 1]]

R = PolynomialRing(F, names=[f"x{i}" for i in range(ACTIVE_N)], order="degrevlex")
x = R.gens()
polys = []
for k in range(m):
    f = R(C[k] - target[k])
    for i in range(ACTIVE_N):
        if P[k][i, i]:
            f += R(P[k][i, i]) * x[i]^2
        if L[k][i]:
            f += R(L[k][i]) * x[i]
        for j in range(i + 1, ACTIVE_N):
            coefficient = F(2) * P[k][i, j]
            if coefficient:
                f += R(coefficient) * x[i] * x[j]
    polys.append(f)
polys.extend(variable^3 - variable for variable in x)
I = R.ideal(polys)
print(f"block={BLOCK} active_variables={ACTIVE_N} equations={len(polys)}", flush=True)

started = time.time()
solutions = None
errors = []
try:
    solutions = I.variety(ring=F, algorithm="msolve")
    print(f"variety(msolve) returned {len(solutions)} solutions", flush=True)
except Exception as exc:
    errors.append(f"variety(msolve): {type(exc).__name__}: {exc}")
    print(errors[-1], flush=True)

if not solutions:
    try:
        G = I.groebner_basis(algorithm="msolve")
        print(f"groebner_basis(msolve) size={len(G)}", flush=True)
        J = R.ideal(G)
        solutions = J.variety(ring=F)
        print(f"variety(from msolve basis) returned {len(solutions)} solutions", flush=True)
    except Exception as exc:
        errors.append(f"groebner_basis(msolve): {type(exc).__name__}: {exc}")
        print(errors[-1], flush=True)

if not solutions:
    raise RuntimeError("msolve did not return a solution: " + " | ".join(errors))

elapsed = time.time() - started
for candidate in solutions:
    solution = [int(candidate[x[i]]) for i in range(ACTIVE_N)] + [0] * (n - ACTIVE_N)
    good = True
    vx = vector(F, solution)
    for k in range(m):
        if vx * P[k] * vx + L[k] * vx + C[k] != target[k]:
            good = False
            break
    if not good:
        continue
    with open(OUT, "w", encoding="utf-8") as fh:
        fh.write(f"block={BLOCK}\n")
        fh.write("trits=" + "".join(map(str, solution)) + "\n")
        fh.write("backend=msolve\n")
        fh.write(f"elapsed={elapsed:.6f}\n")
    print("verified trits=" + "".join(map(str, solution)), flush=True)
    break
else:
    raise RuntimeError("no returned solution passed all 53 public equations")
