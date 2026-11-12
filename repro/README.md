# agent-cryptid — Reproduction Package

**agent-cryptid** is an identity-credential-delegation-notarization middleware for
software agents (an "agent credential identity platform"). This package reproduces
the full evaluation of the accompanying manuscript, including the cryptographic
core, the threat/performance evaluation, the machine-checked formal verification,
the post-quantum native measurements, and the domestic operating-system
portability check.

---

## 1. Package layout

```
repro/
├── README.md                # this file
├── LICENSE                  # MIT
├── requirements.lock        # exact dependency lock (tiered; core = none)
├── run_repro.py             # one-click entry point (tier selection)
├── expected_results.json    # paper-reported values for verification
├── proto/                   # the cryptographic core (pure Python, stdlib only)
│   ├── entrypoint.py        # CLI: --check / --smoke / --http / demo
│   ├── sm2.py sm2_fast.py sm2_jac.py sm9.py sm9_pairing.py
│   ├── identity.py credential.py delegation.py revocation.py
│   ├── audit_anchor.py persistence.py agent_platform.py auth.py
│   ├── nonce_store.py runtime.py demo.py
│   ├── mldsa.py slhdsa.py shake.py        # post-quantum prototypes (stdlib only)
│   └── check_*.py           # per-module self-checks (SELF_TEST)
└── research/
    ├── eval_framework.py    # E1-E7, E10, E11 evaluation driver
    ├── e12_ablation.py e13_concurrency.py e14_stat_significance.py
    ├── e15_c_backend.py e17_case_study.py verify_claims.py
    └── formal/              # formal verification
        ├── e16_offline.py   # Tamarin-equivalent S1-S5 (pure Python, bounded)
        ├── e18_offline.py   # CryptoVerif-equivalent Lemmas 1-3 (pure Python)
        ├── run_all_offline.sh
        ├── *.spthy *.pv     # model files for the online provers
        └── *.md             # verification notes / theorems
```

## 2. Requirements

- **OS**: Linux x86_64 (developed on Ubuntu 24.04 / openEuler 24.03). Windows
  works for Tier 0 (core) only; the eval/formal tiers assume a POSIX shell.
- **Python**: 3.9+ (verified 3.11 and 3.13). No `pip install` needed for the core.
- **Hardware for timing tiers**: a quiet (unloaded) machine. Absolute latencies
  (E1/E2/E6) are load-sensitive and are reported as median / P95 / P99; the
  correctness tiers (E3/E4/E5/E7, formal) are load-independent.
- **Optional external tools** (not bundled): Tamarin Prover 1.12, ProVerif 2.05,
  CryptoVerif 2.12, liboqs (native PQ). Offline equivalents are bundled.

## 3. Quick start — Tier 0 (core, zero dependencies)

The cryptographic core is self-contained and needs **no third-party packages**:

```bash
cd proto
python entrypoint.py            # end-to-end demo (issue -> sign -> verify -> revoke)
python entrypoint.py --check    # full self-check suite (SM2/SM3/SM9/KAT + PQ)
python entrypoint.py --smoke    # 10-API platform smoke
```

`--check` runs every module's `SELF_TEST`. On success the grand-total line reads
`GRAND TOTAL PASS=1075 FAIL=0` (verified 2026-11-12, Python 3.13, clean artifact;
no stale `*_report.txt` present). The suite
asserts: SM2/SM3/SM9 known-answer tests, credential issue/verify round-trips,
scope-convergence on delegation, Merkle accumulator revocation, audience
binding, nonce anti-replay, algorithm-tier anti-downgrade, failure-closed
hybrid (SM2 ∧ ML-DSA) verification, plus the v3.0 closure blocks — hardware
root (HSM/PKCS#11 19/19), cross-domain revocation federation (13/13),
chain-notarization ledger (14/14), and GM/T compliance self-check (20/20).

## 4. Full reproduction tiers

### Tier A — Evaluation framework (E1-E7, E10, E11)

```bash
cd research
python eval_framework.py --quick     # smoke (seconds); correctness + sanity timing
python eval_framework.py --full      # paper-scale (≈10-20 min); run on a quiet host
python eval_framework.py --outdir results/
```

Output: `results/eval_results_<ts>.json` (all raw numbers),
`results/eval_E*.csv` (tables), `results/eval_fig_*.png` (when matplotlib present).

- E1 scalability, E2/E6 baseline comparison, E3 threat-driven security (all must
  *reject*), E4 failure-closed hybrid, E5 KAT, E7 agile migration.
- E10 requires the A2A/MCP venv (see `requirements.lock`, Tier B).
- E11 parallelism (GIL vs multiprocessing) and the OceanBase CE equivalence check
  (23 checks) are separate scripts (`e13_concurrency.py`, `oceanbase_backend.py`).

### Tier B — Machine-checked formal verification

Two provers were used; both **offline pure-Python equivalents are bundled** and
reproduce the machine-checked outcome without installing the provers:

```bash
cd research/formal
python e16_offline.py      # S1-S5, 7133 states, all PASS
python e18_offline.py      # Lemmas 1-3, all PASS
```

For the *prover-backed* results (recommended for reviewers who want the
machine-checked transcript), install Tamarin / ProVerif / CryptoVerif and run the
bundled models `*.spthy` / `*.pv`. The exact commands, package versions and the
prover log excerpts are in `formal/README.md` and the `*.md` notes.

### Tier C — Native post-quantum measurements (manuscript §Scalability/Performance)

The manuscript reports liboqs native timings for ML-DSA-65 and SLH-DSA (full
FIPS 205 parameter sets). Reproduce by building liboqs from source
(`requirements.lock`, Tier D) and linking a C benchmark against `liboqs.a`
(`-lcrypto -lpthread -lm`). The pure-Python prototypes are already exercised by
Tier 0; the native numbers are *not* reproduced by `--check` because they require
a C toolchain and were measured on a separate quiet host.

### Tier D — A2A/MCP integration (E10)

```bash
python -m venv envs/a2amcp && envs/a2amcp/bin/pip install a2a-sdk==1.2.3 mcp==2.3.0 mcp-types==2.3.0
# then run the E10 integration attack suite via eval_framework.py --e10
```

### Tier E — Domestic (Chinese) operating-system portability

The manuscript verifies the OS layer of the domestic-stack requirement on
**openEuler 24.03 LTS-SP4**. Reproduce by building a chroot user space and running
the core smoke inside it (the same `proto/` code, no modification):

```bash
# On a host with the openEuler repo reachable (e.g. Huawei Cloud mirror):
sudo dnf --installroot=/opt/oe --releasever=24.03 --nogpgcheck \
     --setopt=install_weak_deps=False \
     --repofrompath=oe,https://mirrors.huaweicloud.com/openeuler/openEuler-24.03-LTS-SP4/OS/x86_64/ \
     --disablerepo=* --enablerepo=oe \
     install python3 bash coreutils
sudo chroot /opt/oe /bin/bash -c 'cd /root/proj && python3 smoke.py'
# expect: SM2 issue/sign/verify=True, SM3 KAT PASS, OPEN_EULER_SMOKE_OK
```

## 5. Expected results & verification

`expected_results.json` records the manuscript values. `run_repro.py --verify`
runs Tier 0 + Tier B and compares against them. Timing tiers are machine- and
load-dependent: the package verifies *correctness assertions* and *relative
relationships* (e.g. agent-cryptid vs UCAN ≈ 18×, E3 14/14 reject, E4 fail-closed,
E5 KAT 54/54) rather than absolute latencies; absolute latencies are reported with
warmup + percentile statistics for comparison on any quiet host.

## 6. Verification summary

| Tier | What it proves | How | Bundled | Result |
|------|----------------|-----|---------|--------|
| 0 | Crypto core correctness | `--check` | yes | PASS=0 FAIL |
| A | Threat/perf/baseline | eval_framework | yes | E3 14/14, E4 fail-closed, E5 KAT |
| B | Formal security (S1-S5, L1-L3) | offline verifiers | yes | all PASS |
| C | Native PQ speed | liboqs C | source | ML-DSA-65 0.095ms, SLH-DSA full |
| D | A2A/MCP boundary | E10 | venv | 26/26 |
| E | Domestic OS portability | openEuler chroot | script | SM2/SM3 PASS |

## 7. Known deviations & honest disclosure

- Absolute latencies are reported per-host; only the correctness/rejection
  assertions and the *relative* speedups are portable. The manuscript's
  "quiet-host" numbers were captured on an isolated 2-core VM (load ≈ 0).
- The hardware-rooted key path (v3.0) and on-chain notarization are interface
  stubs (`SecureKeyBackend`, ledger-agnostic anchor) — deliberately out of the
  verified scope and disclosed as future work.
- The commercial-cryptography certification (GM/T 0028/0008) is an external
  administrative step requiring vendor hardware; it is not part of this artifact.

---
*Reproduction package generated 2026-11-11. Please cite the manuscript and this
package when reporting reproduction results.*
