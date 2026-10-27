#!/usr/bin/env python3
"""Independent fixed-phase, sampled minimax fit. Not a PhaseOpt certificate.

Offline dependencies: numpy, scipy, mpmath. Runtime only loads frozen text files.
The LP constraints use scipy.optimize.linprog's explicit free coefficient bounds:
https://docs.scipy.org/doc/scipy/reference/generated/scipy.optimize.linprog.html
"""
import argparse
import hashlib
import json
from pathlib import Path
import numpy as np
import mpmath as mp
from scipy.optimize import linprog
import scipy


def basis(x, phase, degree):
    theta = 2 * np.pi * float(phase) * np.asarray(x)[:, None] * np.arange(1, degree + 1)
    return np.column_stack((np.ones(len(x)), np.cos(theta), np.sin(theta)))


def generate(degree, phase, output):
    x = np.linspace(-1, 1, 8193)
    grid = np.linspace(-1, 1, 200001)
    dense = basis(grid, phase, degree)
    target = np.maximum(grid, 0)
    for iteration in range(8):
        mat = basis(x, phase, degree)
        y = np.maximum(x, 0)
        A = np.vstack((np.column_stack((mat, -np.ones(len(x)))),
                       np.column_stack((-mat, -np.ones(len(x))))))
        objective = np.zeros(mat.shape[1] + 1)
        objective[-1] = 1
        result = linprog(objective, A_ub=A, b_ub=np.r_[y, -y],
                         bounds=[(None, None)] * mat.shape[1] + [(0, None)],
                         method='highs', options={'dual_feasibility_tolerance': 1e-9,
                                                 'primal_feasibility_tolerance': 1e-9})
        if not result.success:
            raise RuntimeError(result.message)
        coeff = result.x[:-1]
        residual = dense @ coeff - target
        err = float(np.max(np.abs(residual)))
        if err <= result.fun + 2e-9:
            break
        peaks = np.flatnonzero((np.abs(residual[1:-1]) >= np.abs(residual[:-2])) &
                               (np.abs(residual[1:-1]) >= np.abs(residual[2:]))) + 1
        x = np.unique(np.r_[x, grid[peaks], -1, 0, 1])
    # Validate the frozen binary64 realization, including endpoint and kink.
    payload = ['RELU_TRIG_V1', f'{phase} {degree} {err:.17g}', f'{coeff[0]:.17g}']
    for k in range(degree):
        payload.append(f'{coeff[k+1]:.17g} {coeff[k+1+degree]:.17g}')
    payload = '\n'.join(payload) + '\n'
    output.mkdir(parents=True, exist_ok=True)
    path = output / f'relu_d{degree}.txt'
    path.write_text(payload)
    metadata = {'source': 'independent fixed-phase adaptive grid linear program',
                'certificate': None, 'phase_decimal': phase, 'degree': degree,
                'grid_points': len(grid), 'sampled_max_error': err,
                'lp_error': float(result.fun), 'iterations': iteration + 1,
                'coefficient_l1': float(np.abs(coeff).sum()),
                'numpy': np.__version__, 'scipy': scipy.__version__,
                'sha256': hashlib.sha256(payload.encode()).hexdigest()}
    path.with_suffix('.json').write_text(json.dumps(metadata, indent=2) + '\n')
    print(json.dumps(metadata))


def carrier(output):
    mp.mp.dps = 90
    K, doublings, degree = 12, 3, 31
    angle = 2 * mp.pi * K / (2 ** doublings)
    # Jacobi-Anger expansion of exp(i * angle * y), |y| <= 1.
    coeff = [(1 if k == 0 else 2) * (mp.j ** k) * mp.besselj(k, angle)
             for k in range(degree + 1)]
    rows = ['COMPLEX_CARRIER_V1', f'{K} {doublings} {degree}']
    rows.extend(f'{float(mp.re(c)):.17g} {float(mp.im(c)):.17g}' for c in coeff)
    (output / 'carrier_k12_d31.txt').write_text('\n'.join(rows) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=Path(__file__).parent / 'functional_params')
    args = parser.parse_args()
    generate(15, '0.4494', args.output)
    generate(31, '0.47295', args.output)
    carrier(args.output)
