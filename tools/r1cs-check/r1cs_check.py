#!/usr/bin/env python3
"""Determinism screen for R1CS constraint systems.

Answers one question: given the circuit's declared inputs, is every declared
output forced to a single value by the constraints?

If not, a malicious prover may be able to choose an output -- the
under-constrained-circuit bug class, which is the one that matters and the one
differential testing cannot find (see docs/CIRCUIT_TESTING.md).

The analysis is sound in the direction that counts: a signal reported
DETERMINED really is forced. It is incomplete in the other direction -- it
propagates only through constraints that are linear in the remaining unknowns,
so it reports false positives on gadgets whose uniqueness needs case analysis
(IsZero being the canonical one). Treat UNDETERMINED as "look at this", not as
"this is broken". It is a screen, not a prover.

Input format (JSON):

    {
      "prime": "218882428718392752...",   # optional, defaults to BN254 scalar
      "signals": ["one", "in", "out", ...],
      "inputs":  [1],                     # indices; signal 0 is always the constant 1
      "outputs": [2],
      "constraints": [
        {"a": {"1": 1}, "b": {"3": 1}, "c": {"0": 1, "2": -1}}
      ]
    }

Each constraint means (A . w) * (B . w) = (C . w), where A, B, C are sparse
linear combinations over the witness vector w and w[0] == 1.

Usage:  r1cs_check.py FILE.json [FILE.json ...]
        r1cs_check.py --selftest
Exit:   0 all outputs determined, 1 some output undetermined, 2 bad input.
"""

import json
import sys

BN254_SCALAR = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)

CONST = 0  # witness index of the constant 1


class Circuit:
    def __init__(self, spec):
        self.prime = int(spec.get("prime", BN254_SCALAR))
        self.signals = list(spec["signals"])
        self.inputs = set(spec.get("inputs", []))
        self.outputs = set(spec.get("outputs", []))
        self.constraints = [
            (self._lc(c.get("a", {})), self._lc(c.get("b", {})), self._lc(c.get("c", {})))
            for c in spec["constraints"]
        ]
        n = len(self.signals)
        for group in (self.inputs, self.outputs):
            for i in group:
                if not 0 <= i < n:
                    raise ValueError("signal index %d out of range" % i)

    def _lc(self, d):
        """Sparse linear combination: {index: coefficient mod p}, zeros dropped."""
        out = {}
        for k, v in d.items():
            i, c = int(k), int(v) % self.prime
            if c:
                out[i] = (out.get(i, 0) + c) % self.prime
                if out[i] == 0:
                    del out[i]
        return out

    def name(self, i):
        return self.signals[i] if i < len(self.signals) else "sig%d" % i


def _const_value(lc, prime):
    """If lc is a compile-time constant, return it; else None."""
    if not lc:
        return 0
    if set(lc) == {CONST}:
        return lc[CONST] % prime
    return None


def _deduce(lc_a, lc_b, lc_c, known, prime):
    """Try to force exactly one unknown signal from one constraint.

    Returns the signal index newly determined, or None.

    Rules, all of which preserve soundness:

      1. If both A and B are fully known, (A.w)(B.w) is a fixed field element,
         so the constraint is linear in C. One unknown in C with a nonzero
         constant coefficient is therefore forced.

      2. If exactly one of A, B is fully known -- say A, with value alpha --
         the constraint reads alpha*(B.w) = C.w, linear in the unknowns of
         B and C together. It forces a signal only when that signal's
         coefficient is a nonzero *constant*:
           - an unknown appearing only in C has coefficient -C[s]: always safe;
           - an unknown appearing in B has coefficient alpha*B[s] - C[s],
             which depends on alpha. Safe only when A is a compile-time
             constant, so alpha is known at analysis time rather than at
             witness time.
         This distinction is the whole reason `in * out === 0` does not let us
         conclude anything about `out`: the coefficient is `in`, which is zero
         for one of the inputs the prover may choose.

      3. If both A and B carry unknowns the constraint is genuinely quadratic
         in them, and linear propagation says nothing.
    """
    unk_a = [s for s in lc_a if s not in known]
    unk_b = [s for s in lc_b if s not in known]
    unk_c = [s for s in lc_c if s not in known]

    if unk_a and unk_b:
        return None  # rule 3

    if not unk_a and not unk_b:  # rule 1
        if len(unk_c) == 1:
            return unk_c[0]
        return None

    # rule 2: exactly one side has unknowns; call the known side A.
    if unk_a:
        lc_a, lc_b = lc_b, lc_a
        unk_b = unk_a

    alpha = _const_value(lc_a, prime)

    # A degenerate but real case: if A is the constant zero, the product
    # vanishes and B's unknowns drop out of the constraint entirely.
    if alpha == 0:
        return unk_c[0] if len(unk_c) == 1 else None

    pool = set(unk_b) | set(unk_c)
    if len(pool) != 1:
        return None
    s = next(iter(pool))

    if s not in lc_b:
        return s  # coefficient is -C[s], a nonzero constant

    if alpha is None:
        return None  # coefficient depends on a witness-time value
    coeff = (alpha * lc_b.get(s, 0) - lc_c.get(s, 0)) % prime
    return s if coeff else None


def analyse(circuit):
    """Propagate to a fixpoint. Returns the set of determined signal indices."""
    known = {CONST} | set(circuit.inputs)
    changed = True
    while changed:
        changed = False
        for lc_a, lc_b, lc_c in circuit.constraints:
            s = _deduce(lc_a, lc_b, lc_c, known, circuit.prime)
            if s is not None and s not in known:
                known.add(s)
                changed = True
    return known


def report(circuit, label=""):
    known = analyse(circuit)
    undetermined_outputs = sorted(circuit.outputs - known)
    free_internal = sorted(
        i
        for i in range(len(circuit.signals))
        if i not in known and i not in circuit.outputs and i != CONST
    )

    head = "%s: " % label if label else ""
    if undetermined_outputs:
        print(
            "%sUNDETERMINED OUTPUT(S): %s"
            % (head, ", ".join(circuit.name(i) for i in undetermined_outputs))
        )
        print("    a prover may be able to choose these; inspect the constraints")
    else:
        print("%sok -- every declared output is forced by the inputs" % head)
    if free_internal:
        print(
            "    (informational) free internal signals: %s"
            % ", ".join(circuit.name(i) for i in free_internal)
        )
    return 1 if undetermined_outputs else 0


# --------------------------------------------------------------------------
# Self-tests. These double as the worked examples in docs/CIRCUIT_TESTING.md.
# --------------------------------------------------------------------------

# out = a * b. Textbook, fully determined.
MUL = {
    "signals": ["one", "a", "b", "out"],
    "inputs": [1, 2],
    "outputs": [3],
    "constraints": [{"a": {"1": 1}, "b": {"2": 1}, "c": {"3": 1}}],
}

# out = a * b * c through an intermediate. Determined, two constraints deep,
# and it exercises the fixpoint rather than a single pass.
MUL3 = {
    "signals": ["one", "a", "b", "c", "t", "out"],
    "inputs": [1, 2, 3],
    "outputs": [5],
    "constraints": [
        {"a": {"1": 1}, "b": {"2": 1}, "c": {"4": 1}},
        {"a": {"4": 1}, "b": {"3": 1}, "c": {"5": 1}},
    ],
}

# IsZero with the guard constraint omitted -- the canonical under-constrained
# circuit. `inv` is free, so out = 1 - in*inv is whatever the prover wants.
ISZERO_BROKEN = {
    "signals": ["one", "in", "out", "inv"],
    "inputs": [1],
    "outputs": [2],
    "constraints": [
        {"a": {"1": 1}, "b": {"3": 1}, "c": {"0": 1, "2": -1}},
    ],
}

# The correct IsZero, with `in * out === 0` restored. Sound in reality, but
# proving it needs a case split on in == 0, which this analysis cannot do --
# so it is the documented false positive.
ISZERO_CORRECT = {
    "signals": ["one", "in", "out", "inv"],
    "inputs": [1],
    "outputs": [2],
    "constraints": [
        {"a": {"1": 1}, "b": {"3": 1}, "c": {"0": 1, "2": -1}},
        {"a": {"1": 1}, "b": {"2": 1}, "c": {}},
    ],
}

# A dangling boolean selector: b is never constrained to {0,1} and never tied
# to an input, so out is free. Distinct from IsZero in that no case analysis
# would rescue it -- this one is genuinely broken.
FREE_SELECTOR = {
    "signals": ["one", "x", "b", "out"],
    "inputs": [1],
    "outputs": [3],
    "constraints": [{"a": {"2": 1}, "b": {"1": 1}, "c": {"3": 1}}],
}


def selftest():
    cases = [
        ("mul (sound)", MUL, 0),
        ("mul3 (sound, needs fixpoint)", MUL3, 0),
        ("iszero missing guard (BROKEN)", ISZERO_BROKEN, 1),
        ("free selector (BROKEN)", FREE_SELECTOR, 1),
        ("iszero correct (known false positive)", ISZERO_CORRECT, 1),
    ]
    failures = 0
    for label, spec, expected in cases:
        got = report(Circuit(spec), label)
        if got != expected:
            print("    !! expected exit %d, got %d" % (expected, got))
            failures += 1
    print()
    if failures:
        print("selftest: %d case(s) behaved unexpectedly" % failures)
        return 2
    print("selftest: all 5 cases behaved as documented")
    print("note: the last case is a false positive and is expected to flag;")
    print("      it is why this tool screens rather than decides.")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip())
        return 2
    if argv[1] == "--selftest":
        return selftest()
    worst = 0
    for path in argv[1:]:
        try:
            with open(path) as fh:
                circuit = Circuit(json.load(fh))
        except (OSError, ValueError, KeyError) as exc:
            print("%s: cannot read as R1CS: %s" % (path, exc))
            return 2
        worst = max(worst, report(circuit, path))
    return worst


if __name__ == "__main__":
    sys.exit(main(sys.argv))
