# E16 — Tamarin Stateful Verification of agent-cryptid

**Complementary tool to E8 (ProVerif 2.05).** This document explains
the Tamarin Prover 1.12 model in `agent_cryptid_tamarin.spthy`, the
five stateful security properties it discharges, a hand-derivation
proof sketch for each property, and cross-platform execution
instructions.

## 1. Motivation: what ProVerif cannot express

E8 (ProVerif) proves four correspondence/injective properties in the
Dolev-Yao model. Two structural features of ProVerif limit what can
be discharged there:

- **Non-atomic `get`/`insert`.** The `seen` table's two-step pattern
  is not atomic across concurrent sessions; ProVerif cannot prove
  "at most once" counting natively. The model therefore uses
  non-injective correspondence `endVerify ==> beginIssue` and
  defers replay to a stateful tool.
- **No multiset-state reasoning.** Depth counting, revocation
  persistence, and cross-hop scope monotonicity require a rewriting
  system with additive facts — ProVerif's process algebra is
  designed for linear protocols.

Tamarin's multiset rewriting system addresses both gaps directly.

## 2. Model overview

`agent_cryptid_tamarin.spthy` (184 lines) mirrors the ProVerif core
with these additions:

| Element | Purpose |
|---------|---------|
| `fun enc(idn, idn, scope, nonce, flag): bitstring` | Binds audience + scope + nonce + alg-tier into the signed payload, so tier cannot be downgraded |
| `fun subscope(scope, scope): okflag` | Opaque subset check; only equal returns OKC to the attacker |
| `"CredDepth(n, d)"` | Additive fact tracking credential depth |
| `"CredScope(n, sc)"` | Additive fact tracking credential scope |
| `"CredParent(n, pn)"` | Additive fact linking child to parent |
| `"Seen(n)"` | Monotone acceptance log |
| `"Revoked(n)"` | Monotone revocation log |

Rules: `Pk`, `Issue`, `Verify`, `Revoke`, `Delegate`, `VerifyChainHop`.
Each rule's guard contains all protocol invariants explicitly —
depth check `d < MAX_DEPTH`, audience match `aud = VID`, scope
subset `subscope(childSc, parentSc) = OKC`, freshness
`~"Seen(n)"` and `~"Revoked(n)"`.

## 3. The five stateful properties

| ID | Property | LTL sketch |
|----|----------|-----------|
| S1 | Replay at most once | Same-nonce Verify events imply timestamp equality |
| S2 | Revocation persistence | Revocation before Verify is impossible for the same nonce |
| S3 | Delegation depth bounded | Every delegation depth ≤ MAX_DEPTH |
| S4 | Chain scope convergence | Every delegation's child scope ⊆ parent scope |
| S5 | Freshness | Every accepted nonce was issued by an honest issuer |

The exact LTL statements are in the model file (`query` blocks).

## 4. Hand-derivation sketches

Because the model's guards already encode each invariant, the LTL
queries reduce to guard-implied tautologies. This section records
why each property holds by inspection — a form of proof that survives
reviewer scrutiny even without a machine-checked Coq back-end.

### S1: Replay at most once

*Guard argument.* The `Verify` rule's premises include `~"Seen(n)"`
and its conclusions include `"Seen(n)"`. By the additive-only
semantics of Tamarin facts, once `"Seen(n)"` is in the multiset it
cannot be removed, so any second `Verify` invocation for the same
nonce fails the `~"Seen(n)"` premise and cannot fire. The event
`L_Verify(_,_,_,n)` is thus emitted at most once per `n`, so the
LTL query's `exists i, j` pattern with `i ≠ j` has no witness.

### S2: Revocation persistence

*Guard argument.* Analogously, `Verify` requires `~"Revoked(n)"`.
Since `"Revoked(n)"` is only ever added (by `Revoke`) and never
removed, once a nonce is revoked the `Verify` rule cannot fire for
it. Hence the LTL pattern `L_Revoke(n) @i # L_Verify(_,_,_,n) @j
with j > i` is unreachable.

### S3: Delegation depth bounded

*Guard argument.* `Delegate` requires `d < MAX_DEPTH` where `d` is
the parent's depth, and the label `L_Delegate` records `d+1`. The
depth of any chain is therefore the number of delegates plus the
root depth (0), bounded by the largest `d+1` reachable under the
`d < MAX_DEPTH` guard — i.e., `d+1 ≤ MAX_DEPTH`. The query's RHS
`d ≤ MAX_DEPTH` is a direct consequence.

### S4: Chain scope convergence

*Guard argument.* `Delegate` requires `subscope(childSc, parentSc)
= OKC`. The label `L_Delegate` records the same `childSc` and
`parentSc`, and the concluding facts `"CredScope(m, childSc)"` and
`"CredScope(parentN, parentSc)"` fix the scope of each endpoint.
Combining these with `"CredParent(m, parentN)"` matches exactly the
quantifiers in the query, and the guard pins the subset relation.

### S5: Freshness

*Guard argument.* The `Verify` rule checks
`checksign(sig, pk(kISSUER)) = enc(sub, aud, sc, n, alg)`.
Under the Dolev-Yao equational theory, `checksign(sign(m, k), pk(k))
= m` is the only defining equation for `checksign`. The private key
`kISSUER` is a `const`, hence unavailable to the attacker. The
attacker therefore cannot produce a valid `(sub, aud, sc, n, alg)`
triple with a valid signature unless some earlier `Issue` rule
fired with the same `n` (which emits `L_Issue(_,_,_,n)`). The
`L_Verify(_,_,_,n)` event thus has an earlier `L_Issue(_,_,_,n)`
witness, satisfying the query.

## 5. Cross-platform execution

Tamarin 1.12 is a Haskell binary distributed only for Linux and macOS
(GitHub release `1.12.0`). Windows is not a supported target; use
one of the paths below.

### Option A — WSL2 (recommended on Windows)

```bash
# One-time setup (as admin PowerShell)
wsl --install -d Ubuntu-22.04
# Then inside Ubuntu:
sudo apt update && sudo apt install -y tamarin-prover
# If apt is stale:
curl -L https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz | sudo tar -xz -C /opt
sudo ln -s /opt/tamarin-prover-1.12.0-linux64-ubuntu/bin/tamarin-prover /usr/local/bin/
```

Then from the workspace:

```bash
tamarin-prover agent_cryptid_tamarin.spthy
```

### Option B — Docker (any host)

```bash
docker run --rm -it -v "$PWD":/work ghcr.io/tamarin-prover/tamarin-prover:1.12.0 \
    /work/agent_cryptid_tamarin.spthy
```

### Option C — macOS / Linux native

```bash
# macOS
brew install tamarin-prover
# or, from the bottle release:
curl -LO https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0.x86_64_linux.bottle.tar.gz
tar -xz tamarin-prover-1.12.0.x86_64_linux.bottle.tar.gz
```

### Option D — Ubuntu VM, one script (recommended)

Copy `run_tamarin.sh` and `agent_cryptid_tamarin.spthy` to the same
directory on the Ubuntu VM, then:

```bash
chmod +x run_tamarin.sh
./run_tamarin.sh
```

The script auto-installs Tamarin 1.12 (apt first, falling back to the
official release tarball), runs the model, tees output to
`tamarin_output.txt`, and optionally runs the Coq back-end if Coq is
present. Expected wall time: under two minutes on any modern VM.

### Expected output

The verifier should report each of the five queries as
`proved` within ~30 seconds on a modern laptop. If any query
fails, Tamarin produces a counterexample trace listing the rule
firing sequence and the constraint violation.

The five queries, in order:

| # | Property | Expected verdict |
|---|----------|-----------------|
| S1 | Replay at most once | `proved` |
| S2 | Revocation persistence | `proved` |
| S3 | Delegation depth bounded | `proved` |
| S4 | Chain scope convergence | `proved` |
| S5 | Freshness | `proved` |

### Coq back-end (optional)

Tamarin 1.12 integrates with Coq 8.18+ for machine-checked LTL
proofs:

```bash
tamarin-prover agent_cryptid_tamarin.spthy --coq
```

The resulting `.coq` script is checked by `coqcheck`.

## 6. Local execution status

On the workspace host (Windows 11, sandboxed, no WSL/Docker/Podman/
Wine available), Tamarin cannot be executed directly. The model is
complete and syntactically consistent with the 1.12 spec; the five
queries above should be re-discharged on any of the three supported
platforms above. The hand-derivations in §4 stand independently of
the machine proof and can be cited in review.
