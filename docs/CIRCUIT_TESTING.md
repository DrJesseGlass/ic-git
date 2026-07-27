# Testing a circuit compiler you wrote yourself

Design for the test harness that has to exist alongside the R1CS backend
proposed in ROADMAP.md "R5-alt". Written 2026-07-26.

REPRODUCIBLE_BUILD.md and ic-vote/ZK.md both previously said the mitigation
for circuit-compiler soundness bugs is "differential testing against Circom or
Noir on random witnesses." **That prescription is wrong in two specific ways.**
Correcting it is most of this document.

## 1. Two corrections

**Random witnesses test nothing.** A witness is an assignment to every signal
in the system, and a random vector violates the first constraint with
overwhelming probability. Both compilers reject, agreement is 100%, and the
number measures nothing. Worse, witnesses are not even comparable across
compilers: the two systems have different signal counts, different internal
layouts, and different orderings. The only shared vocabulary is the circuit's
**declared inputs and outputs**. Everything below is phrased at that
interface.

**Differential testing cannot find the bug we are most afraid of.** An
under-constrained circuit is one where the constraints fail to pin down a
signal, so a malicious prover can choose it. The honest witness generator
still produces the honest value, so on every honest input both compilers agree
and both accept. Two compilers can be under-constrained in *different* ways
and still agree on every test you run, because the test only ever exercises
honest witnesses. Differential testing compares what the circuit *computes*;
under-constraining is about what the circuit *permits*. Different question.

So the single recommendation splits into three axes with different tools, and
only the first is differential.

## 2. Axis 1 -- semantic equivalence (differential)

*Catches:* frontend and codegen divergence -- the DSL parsing precedence
differently, mis-lowering a subtraction, getting field reduction wrong,
mishandling a sub-circuit call.

*Method:* not random witnesses. Random **inputs**, run through each
toolchain's own witness generator, comparing declared outputs.

    for trial in 1..N:
        inputs   = random field elements for the circuit's declared inputs
        w_ours   = our_witness_generator(circuit, inputs)
        w_theirs = circom_witness_generator(circuit, inputs)
        assert outputs_of(w_ours) == outputs_of(w_theirs)
        assert our_r1cs.satisfied_by(w_ours)
        assert their_r1cs.satisfied_by(w_theirs)

*Higher yield: random circuits, not just random inputs.* Fixing one circuit
and varying inputs explores a thin slice. Generating random *programs* in the
subset both languages accept -- nested arithmetic, sub-circuit calls at
varying depth, constants at boundary values (0, 1, p-1, p-2) -- is where
compiler bugs actually surface. Same comparison, one level up.

*A cross-check worth having, cheap once both generators exist:* take the
witness produced by the other toolchain, map it through the shared
input/output interface, and confirm our constraint system accepts a witness
our own generator derives for those same inputs. This catches the case where
both compilers compute the same function but ours constrains it wrongly.

*Scope consequence for R5-alt.* All of this needs a **witness generator** for
the DSL, not only an R1CS emitter. A constraint system alone cannot be tested
this way -- you need something that, given inputs, produces the assignment.
That is a second backend and R5-alt's estimate has to include it. Easy to
miss, and everything in this axis is blocked on it.

## 3. Axis 2 -- determinism (not differential)

*Catches:* under-constraining. The bug class that lets a prover forge, and the
one axis 1 is blind to.

*Question:* given the declared inputs, is every declared output forced to a
single value by the constraints?

Note the phrasing. It is not "is the whole witness unique" -- internal signals
are often legitimately free. Correct `IsZero` leaves its `inv` signal
completely unconstrained when the input is zero, and it is still a sound
gadget, because `out` is pinned regardless. Uniqueness of *outputs* given
*inputs* is the property that matters.

*Tool, buildable now:* `tools/r1cs-check/r1cs_check.py`. It propagates from
the inputs to a fixpoint, marking a signal determined whenever some constraint
becomes linear in exactly one remaining unknown *with a nonzero constant
coefficient*. Anything still unmarked at the fixpoint gets reported.

The constant-coefficient condition is the subtle part and it is load-bearing.
In correct `IsZero`, the guard constraint is `in * out === 0`, which is linear
in `out` -- but the coefficient is `in`, a value the prover chooses, and it can
be zero. Concluding `out == 0` from it would be unsound. The tool refuses, and
that refusal is why it reports a false positive on correct `IsZero`.

The analysis is **sound but incomplete**: DETERMINED is trustworthy,
UNDETERMINED means "look at this." Run `--selftest` for the five worked cases:

    mul (sound):                            ok
    mul3 (sound, needs fixpoint):           ok
    iszero missing guard (BROKEN):          UNDETERMINED OUTPUT(S): out
    free selector (BROKEN):                 UNDETERMINED OUTPUT(S): out
    iszero correct (known false positive):  UNDETERMINED OUTPUT(S): out

The third case is the canonical Circom footgun -- drop `in * out === 0` and
`inv` goes free, so `out = 1 - in*inv` becomes whatever the prover likes. The
screen catches it. The fifth is the documented limit.

*Escalation:* what the screen flags goes to an SMT-based checker over the
prime field (the Picus / Ecne line of work does exactly this, with case
splitting the propagation cannot do). Right division of labour -- the screen is
milliseconds and runs on every commit; SMT is slow and runs on what survives.

## 4. Axis 3 -- cheap structural invariants

Not proof, but nearly free, and they catch gross breakage early:

- **Constraint count and degree, compared across compilers on the same
  source.** The two will not match -- different lowering, different
  optimizations -- but an order-of-magnitude gap means one of them is doing
  something very different, and that is worth a look before anything subtler.
- **Every declared output appears in at least one constraint.** Trivially
  true of correct output, trivially false of a whole class of codegen bugs.
- **No constraint is identically zero**, which is a silently dropped
  constraint and therefore silently dropped security.
- **Determinism of the compiler itself**: compile twice, get byte-identical
  R1CS. Distributed compilation across the worker fleet must equal local
  compilation, exactly as R4 already verifies for wasm.

## 5. What "alongside the compiler" means concretely

The point of building this with the compiler rather than after it is that
axis 2 does not depend on the compiler at all -- it consumes an R1CS, whoever
emitted it. So:

- **Now, before any compiler work.** `r1cs-check` exists and self-tests. Point
  it at Circom's output for the target circuit to validate it against a real
  system rather than hand-written examples.
- **With the R1CS backend.** Axis 3 invariants in CI from the first commit;
  they are a few lines each and they fail loudly.
- **With the witness generator.** Axis 1 turns on. Not before -- and note this
  means the generator should be scheduled early, not treated as a follow-up,
  or the differential harness sits idle behind it.
- **Before anything ships.** SMT escalation for every signal the screen
  flags, plus a written argument for each accepted false positive. "The screen
  flags this and here is why it is nevertheless sound" is a reviewable
  artifact and belongs in the repo next to the circuit.

## 6. The honest limit

None of this proves the compiler correct. Axis 1 samples a space it cannot
exhaust, axis 2 is incomplete without SMT and incomplete-but-slower with it,
and axis 3 is a smoke test. What the three together buy is that a bug has to
survive semantic comparison against a mature compiler, a determinism screen,
and a set of structural invariants -- which is a great deal better than the
status quo for circuits, where the compiler output is checked by nothing at
all.

That gap is the entire argument for compiling circuits on chain under
attestation in the first place. The harness reduces the chance the reviewed
compiler is wrong; it does not establish that the compiler that ran is the
reviewed one. Those are separate problems and this document only addresses the
first.
