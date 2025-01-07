from sage.all import *
import numpy as np

def shortest_vector_mod(weight, coefficients, targets, moduli, return_matrix=False):
    targets = np.array(targets)
    coefficients = np.array(coefficients)
    moduli = np.array(moduli)

    nt = targets.size
    nc = coefficients.size

    assert nt == moduli.size and nc % nt == 0

    targets = matrix(ZZ, targets.reshape(1, nt))
    coefficients = matrix(ZZ, coefficients.reshape(nc // nt, nt))

    W = block_matrix(ZZ, [
        [identity_matrix(ZZ, nc // nt), 0                                            ],
        [0                            , diagonal_matrix(ZZ, [weight] + [weight] * nt)]
    ])

    mat = block_matrix(ZZ, [
        [identity_matrix(ZZ, nc // nt), 0, coefficients                ],
        [0                            , 1, -targets                    ],
        [0                            , 0, -diagonal_matrix(ZZ, moduli)]
    ])

    vecs = (mat * W).LLL() / W

    if return_matrix:
        return vecs

    for vec in vecs:
        vals = vec[:nc // nt] * coefficients
        vals = [val % mod for val, mod in zip(vals, moduli)]
        if matrix(ZZ, 1, nt, vals) == targets:
            return vec[:nc // nt]

    return None

def shortest_vector(weight, coefficients, targets, moduli=None, return_matrix=False):
    if moduli is not None:
        return shortest_vector_mod(weight, coefficients, targets, moduli, return_matrix)

    targets = np.array(targets)
    coefficients = np.array(coefficients)

    nt = targets.size
    nc = coefficients.size

    assert nc % nt == 0

    targets = matrix(ZZ, targets.reshape(1, nt))
    coefficients = matrix(ZZ, coefficients.reshape(nc // nt, nt))

    W = block_matrix(ZZ, [
        [identity_matrix(ZZ, nc // nt), 0                                 ],
        [0                            , diagonal_matrix(ZZ, [weight] * nt)]
    ])

    mat = block_matrix(ZZ, [
        [identity_matrix(ZZ, nc // nt), coefficients],
        [0                            , -targets    ]
    ])

    vecs = (mat * W).LLL() / W

    if return_matrix:
        return vecs

    for vec in vecs:
        if matrix(ZZ, 1, nt, vec[:nc // nt] * coefficients) == targets:
            return vec[:nc // nt]

    return None

def babai(M, target):
    target = vector(ZZ, target)

    G = M.gram_schmidt()[0]
    small = target
    for _ in range(1):
        for i in reversed(range(M.nrows())):
            c = ((small * G[i]) / (G[i] * G[i])).round()
            small -= M[i] * c
    return target - small
