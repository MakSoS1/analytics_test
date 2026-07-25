from sage.all import *
import os
import random
import time

BASE = os.path.dirname(os.path.abspath(__file__))
PUB = os.path.join(BASE, "D3HFERP", "pubkey.txt")
OUT = os.environ.get("RESULT_PATH", os.path.join(BASE, "structure.txt"))
CHART = int(os.environ.get("CHART", "0"))

F = GF(3)

with open(PUB, "r", encoding="utf-8") as fh:
    lines = [line.strip() for line in fh if line.strip()]
q, n, m = map(int, lines[0].split())
assert (q, n, m) == (3, 31, 53)

P = []
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
    pos += 2
assert pos == len(lines)

rng = random.Random(int(0xD3F3_2026 + CHART))
fixed_coeff = sorted(rng.sample(range(m), 20))
fixed_input = sorted(rng.sample(range(n), 11))
free_coeff = [k for k in range(m) if k not in fixed_coeff]
free_input = [i for i in range(n) if i not in fixed_input]
assert len(free_coeff) == 33 and len(free_input) == 20

p_forms = 2
t_vectors = 2
names = []
for a in range(p_forms):
    for k in free_coeff:
        names.append(f"z_{a}_{k}")
for b in range(t_vectors):
    for i in free_input:
        names.append(f"y_{b}_{i}")

R = PolynomialRing(F, names=names, order="degrevlex")
gens = iter(R.gens())
z = [[None for _ in free_coeff] for _ in range(p_forms)]
y = [[None for _ in free_input] for _ in range(t_vectors)]
for a in range(p_forms):
    for u in range(len(free_coeff)):
        z[a][u] = next(gens)
for b in range(t_vectors):
    for u in range(len(free_input)):
        y[b][u] = next(gens)

coeff = []
for a in range(p_forms):
    current = [R(0)] * m
    current[fixed_coeff[a]] = R(1)
    for u, k in enumerate(free_coeff):
        current[k] = z[a][u]
    coeff.append(current)

vectors = []
for b in range(t_vectors):
    current = [R(0)] * n
    current[fixed_input[b]] = R(1)
    for u, i in enumerate(free_input):
        current[i] = y[b][u]
    vectors.append(current)

forms = []
for a in range(p_forms):
    M = matrix(R, n, n)
    for k in range(m):
        ck = coeff[a][k]
        if ck == 0:
            continue
        for i in range(n):
            for j in range(i, n):
                value = ck * R(P[k][i, j])
                M[i, j] += value
                if i != j:
                    M[j, i] += value
    forms.append(M)

eqs = []
for a in range(p_forms):
    for b in range(t_vectors):
        v = vector(R, vectors[b])
        eqs.extend(list(forms[a] * v))

# Only the 40 coordinates of the two oil vectors need field equations.
# Once those are in GF(3), each selected form is recovered by a linear system,
# so its 66 free coefficients automatically lie in GF(3) as well.
y_variables = [variable for row in y for variable in row]
eqs.extend(variable**3 - variable for variable in y_variables)
I = R.ideal(eqs)

print(
    f"chart={CHART} variables={R.ngens()} equations={len(eqs)} "
    f"fixed_coeff={fixed_coeff} fixed_input={fixed_input}",
    flush=True,
)
started = time.time()
try:
    G = I.groebner_basis(algorithm="slimgb")
except Exception:
    G = I.groebner_basis()
elapsed = time.time() - started
print(f"basis_size={len(G)} elapsed={elapsed:.2f}", flush=True)

if len(G) == 1 and G[0] == 1:
    raise RuntimeError("chart has no solution")

solution = {}
for g in G:
    if g.total_degree() != 1:
        continue
    support = []
    for variable in R.gens():
        coefficient = g.monomial_coefficient(variable)
        if coefficient:
            support.append((variable, F(coefficient)))
    if len(support) != 1:
        continue
    variable, a = support[0]
    solution[variable] = F(-g.constant_coefficient()) / a

if len(solution) != R.ngens():
    raise RuntimeError(
        f"chart did not reduce to a unique linear model: solved {len(solution)}/{R.ngens()}"
    )

recovered_coeff = []
for a in range(p_forms):
    row = []
    for k in range(m):
        if k in fixed_coeff:
            row.append(1 if k == fixed_coeff[a] else 0)
        else:
            u = free_coeff.index(k)
            row.append(int(solution[z[a][u]]))
    recovered_coeff.append(vector(F, row))

recovered_forms = []
for row in recovered_coeff:
    M = zero_matrix(F, n, n)
    for k in range(m):
        M += row[k] * P[k]
    recovered_forms.append(M)

stacked = block_matrix([[recovered_forms[0]], [recovered_forms[1]]])
oil = stacked.right_kernel()
if oil.dimension() != 11:
    raise RuntimeError(
        f"candidate forms do not reveal the expected 11-dimensional kernel: {oil.dimension()}"
    )
if any(M.rank() > 20 for M in recovered_forms):
    raise RuntimeError("candidate form has rank above 20")

O = oil.basis_matrix().transpose()
restriction = matrix(F, n * 11, m)
for k in range(m):
    column = P[k] * O
    restriction.set_column(k, vector(F, column.list()))
hidden_forms = restriction.right_kernel()
if hidden_forms.dimension() != 20:
    raise RuntimeError(
        f"annihilator dimension is {hidden_forms.dimension()}, expected 20"
    )

with open(OUT, "w", encoding="utf-8") as fh:
    fh.write(f"chart={CHART}\n")
    fh.write("h0=" + "".join(str(int(v)) for v in recovered_coeff[0]) + "\n")
    fh.write("h1=" + "".join(str(int(v)) for v in recovered_coeff[1]) + "\n")
    fh.write(f"elapsed={elapsed:.3f}\n")
print("Verified hidden-form pair saved", flush=True)
