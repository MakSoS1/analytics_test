#!/usr/bin/env python3
import os
import random
from pathlib import Path

from ortools.sat.python import cp_model

BASE = Path(__file__).resolve().parent
PUB = BASE / "D3HFERP" / "pubkey.txt"
OUT = Path(os.environ.get("RESULT_PATH", str(BASE / "structure-cpsat.txt")))
CHART = int(os.environ.get("CHART", "0"))

lines = [line.strip() for line in PUB.read_text(encoding="utf-8").splitlines() if line.strip()]
q, n, m = map(int, lines[0].split())
assert (q, n, m) == (3, 31, 53)

P = [[[0] * n for _ in range(n)] for _ in range(m)]
pos = 1
for k in range(m):
    values = list(map(int, lines[pos].split()))
    pos += 1
    t = 0
    for i in range(n):
        for j in range(i, n):
            P[k][i][j] = values[t]
            P[k][j][i] = values[t]
            t += 1
    pos += 2
assert pos == len(lines)

rng = random.Random(0xD3F3_2026 + CHART)
fixed_coeff = sorted(rng.sample(range(m), 20))
fixed_input = sorted(rng.sample(range(n), 11))
free_coeff = [k for k in range(m) if k not in fixed_coeff]
free_input = [i for i in range(n) if i not in fixed_input]
assert len(free_coeff) == 33 and len(free_input) == 20

model = cp_model.CpModel()
z = [[model.new_int_var(0, 2, f"z_{a}_{u}") for u in range(33)] for a in range(2)]
y = [[model.new_int_var(0, 2, f"y_{b}_{v}") for v in range(20)] for b in range(2)]

# Product variables are shared by all 31 row equations for a fixed pair.
products = {}
for a in range(2):
    for b in range(2):
        for u in range(33):
            for v in range(20):
                w = model.new_int_var(0, 4, f"w_{a}_{b}_{u}_{v}")
                model.add_multiplication_equality(w, [z[a][u], y[b][v]])
                products[a, b, u, v] = w

for a in range(2):
    k_fixed = fixed_coeff[a]
    for b in range(2):
        i_fixed = fixed_input[b]
        for row in range(n):
            terms = []
            constant = P[k_fixed][row][i_fixed]

            for u, k in enumerate(free_coeff):
                coefficient = P[k][row][i_fixed]
                if coefficient:
                    terms.append(coefficient * z[a][u])

            for v, i in enumerate(free_input):
                coefficient = P[k_fixed][row][i]
                if coefficient:
                    terms.append(coefficient * y[b][v])

            for u, k in enumerate(free_coeff):
                for v, i in enumerate(free_input):
                    coefficient = P[k][row][i]
                    if coefficient:
                        terms.append(coefficient * products[a, b, u, v])

            # Maximum absolute quotient is safely below 2000.
            quotient = model.new_int_var(0, 2000, f"q_{a}_{b}_{row}")
            model.add(sum(terms) + constant == 3 * quotient)

# Search the oil coordinates first; once fixed, all form coefficients are linear.
model.add_decision_strategy(
    [variable for row in y for variable in row],
    cp_model.CHOOSE_MIN_DOMAIN_SIZE,
    cp_model.SELECT_MIN_VALUE,
)
model.add_decision_strategy(
    [variable for row in z for variable in row],
    cp_model.CHOOSE_MIN_DOMAIN_SIZE,
    cp_model.SELECT_MIN_VALUE,
)

solver = cp_model.CpSolver()
solver.parameters.max_time_in_seconds = float(os.environ.get("TIME_LIMIT", "7200"))
solver.parameters.num_search_workers = int(os.environ.get("WORKERS", "4"))
solver.parameters.cp_model_presolve = True
solver.parameters.linearization_level = 2
solver.parameters.log_search_progress = True
status = solver.solve(model)

if status not in (cp_model.OPTIMAL, cp_model.FEASIBLE):
    raise RuntimeError(f"CP-SAT returned {solver.status_name(status)}")

coefficients = []
for a in range(2):
    row = [0] * m
    row[fixed_coeff[a]] = 1
    for u, k in enumerate(free_coeff):
        row[k] = solver.value(z[a][u])
    coefficients.append(row)

vectors = []
for b in range(2):
    row = [0] * n
    row[fixed_input[b]] = 1
    for v, i in enumerate(free_input):
        row[i] = solver.value(y[b][v])
    vectors.append(row)

# Verify the four matrix-vector products exactly modulo 3.
for a in range(2):
    for b in range(2):
        for r in range(n):
            value = 0
            for k in range(m):
                if coefficients[a][k]:
                    for i in range(n):
                        value += coefficients[a][k] * P[k][r][i] * vectors[b][i]
            if value % 3:
                raise RuntimeError(f"verification failed at ({a}, {b}, {r})")

OUT.write_text(
    f"chart={CHART}\n"
    f"h0={''.join(map(str, coefficients[0]))}\n"
    f"h1={''.join(map(str, coefficients[1]))}\n"
    f"branches={solver.num_branches}\n"
    f"conflicts={solver.num_conflicts}\n",
    encoding="utf-8",
)
print("Verified CP-SAT hidden-form pair saved", flush=True)
