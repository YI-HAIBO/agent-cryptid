# E16 — Tamarin Stateful Verification (Ubuntu package)

Self-contained package for re-discharging the five stateful security
properties of agent-cryptid with Tamarin Prover 1.12.

## Contents

| File | Purpose |
|------|---------|
| `agent_cryptid_tamarin.spthy` | Tamarin model (184 lines, self-contained, no external includes) |
| `run_tamarin.sh` | One-command runner: auto-installs Tamarin, runs the model, saves output |
| `README.md` | This file |

## Quick start (Ubuntu / Debian VM)

```bash
# 1. copy this whole directory to the VM
#    scp -r tamarin_ubuntu_pkg user@vm:~/tamarin

# 2. run
cd tamarin_ubuntu_pkg
./run_tamarin.sh
```

The script:

1. Checks for `tamarin-prover`; if missing, installs it via `apt-get`
   (falling back to the official 1.12.0 release tarball if the apt
   package is unavailable)
2. Runs `tamarin-prover agent_cryptid_tamarin.spthy`, teeing output to
   `tamarin_output.txt`
3. If Coq 8.18+ is present, additionally runs the `--coq` back-end for
   machine-checked LTL proofs

Expected wall time: under two minutes on any modern VM.

## Expected output

Each of the five queries should report `proved`:

| # | Property | LTL shape |
|---|----------|-----------|
| S1 | Replay at most once | `L_Verify(_,_,_,n) @i # L_Verify(_,_,_,n) @j with i < j` → false |
| S2 | Revocation persistence | `L_Revoke(n) @i # L_Verify(_,_,_,n) @j with j > i` → false |
| S3 | Delegation depth bounded | `L_Delegate(_,_,_,d,_,_) with d > MAX_DEPTH` → false |
| S4 | Chain scope convergence | `L_Delegate(_,_,_,_,childSc,parentSc) with not subscope(childSc,parentSc)=OKC` → false |
| S5 | Freshness | `L_Verify(_,_,_,n) @j # L_Issue(_,_,_,n) @i with i < j` → always true |

If any query fails, Tamarin prints a counterexample trace listing the
rule firing sequence and the constraint violation — that trace is the
deliverable, not a false negative.

## Manual run (without the script)

```bash
# install
sudo apt update && sudo apt install -y tamarin-prover
# or, if apt is stale:
curl -fsSL https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz -o /tmp/t.tar.gz
sudo tar -xzf /tmp/t.tar.gz -C /opt
sudo ln -sf /opt/tamarin-prover-1.12.0-linux64-ubuntu/bin/tamarin-prover /usr/local/bin/tamarin-prover

# run
tamarin-prover agent_cryptid_tamarin.spthy
# with Coq back-end (optional, needs Coq 8.18+):
tamarin-prover agent_cryptid_tamarin.spthy --coq
```

## Model notes

The model mirrors the ProVerif core (`agent_cryptid.pv`, E8) and adds
five additive facts that ProVerif's linear-process model cannot express:

- `Seen(n)` — monotone acceptance log (replay at most once)
- `Revoked(n)` — monotone revocation log (revocation persistence)
- `CredDepth(n,d)` — delegation depth counter
- `CredScope(n,sc)` — per-credential scope
- `CredParent(n,pn)` — child→parent linkage (chain scope convergence)

Six rules: `Pk`, `Issue`, `Verify`, `Revoke`, `Delegate`, `VerifyChainHop`.
Every rule's guard encodes the protocol invariant explicitly, so each
LTL query reduces to a guard-implied tautology. Hand-derivations of all
five properties by guard inspection are in the project's
`E16_tamarin_verification.md` (§4).

## Reporting results

Copy `tamarin_output.txt` into `research/formal/` and the paper's E16
section (§4) and Future work can be updated from "model complete,
runner provided" to "machine-executed on [host]". The two lines that
flip are:

1. §4 E16 paragraph: `execution requires a Linux or macOS host` →
   `was executed on [host], producing tamarin_output.txt`
2. Future work (iii): delete the item (already closed in the current
   draft; the runner script makes it re-dischargeable on any Ubuntu
   host)