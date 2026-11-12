#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""agent-cryptid reproduction package — one-click entry point.

Usage:
    python run_repro.py                       # Tier 0 core subset + Tier B formal
    python run_repro.py --check               # full core self-check (all modules)
    python run_repro.py --tier A              # eval framework --quick
    python run_repro.py --tier A --full       # eval framework --full (quiet host)
    python run_repro.py --verify              # full check + formal, compare expected

Exit code 0 = all verified; 1 = a tier failed or a mismatch was found.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PROTO = os.path.join(HERE, "proto")
RESEARCH = os.path.join(HERE, "research")
FORMAL = os.path.join(RESEARCH, "formal")
EXPECTED = os.path.join(HERE, "expected_results.json")


def sh(cmd, cwd=None, timeout=1800):
    """Run a command, return (rc, stdout+stderr)."""
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True,
                       timeout=timeout, shell=isinstance(cmd, str))
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def run_core_subset():
    """Fast, deterministic subset of the core (no slow PQ keygen).

    Each check module is imported in a subprocess. If it exposes a
    self_check() that returns (name, ok) pairs we call it and count from
    the return value; otherwise (e.g. check_sm2/check_v01 run their checks
    as an import side-effect and write <mod>_report.txt) we read the report
    file for the RESULT count.
    """
    checks = ["check_sm2", "check_v01", "auth", "revocation", "credential"]
    print("== Tier 0: core subset (%d modules) ==" % len(checks))
    total_pass = total_fail = 0
    for mod in checks:
        script = (
            "import sys; sys.path.insert(0,%r); import %s as _m; "
            "_r = _m.self_check() if hasattr(_m, 'self_check') else None; "
            "print('SUBSET_RESULT %%d %%d' %% ("
            "sum(1 for x in _r if x[1]), sum(1 for x in _r if not x[1]))) "
            "if _r else None"
        ) % (PROTO, mod)
        rc, out = sh([sys.executable, "-c", script], cwd=PROTO, timeout=900)
        p = f = None
        mm = re.search(r"SUBSET_RESULT\s+(\d+)\s+(\d+)", out)
        if mm:
            p, f = int(mm.group(1)), int(mm.group(2))
        if p is None:
            # no self_check() return (import-side-effect module): read the
            # report file the import wrote
            rp = os.path.join(PROTO, "%s_report.txt" % mod)
            if os.path.exists(rp):
                for line in open(rp, encoding="utf-8", errors="replace"):
                    m = re.match(r"RESULT\s+PASS=(\d+)\s+FAIL=(\d+)",
                                 line.strip())
                    if m:
                        p, f = int(m.group(1)), int(m.group(2))
        if p is None:
            # no report either: fall back to exit code
            p, f = (1, 0) if rc == 0 else (0, 1)
        total_pass += p
        total_fail += f
        status = "PASS" if f == 0 else "FAIL"
        print("  %-22s %s  (PASS=%d FAIL=%d)" % (mod, status, p, f))
    print("  core subset total: PASS=%d FAIL=%d" % (total_pass, total_fail))
    return total_pass, total_fail


def run_full_check():
    """Run proto/entrypoint.py --check (all modules)."""
    print("== Tier 0: full core self-check (entrypoint --check) ==")
    rc, out = sh([sys.executable, os.path.join(PROTO, "entrypoint.py"), "--check"],
                 cwd=PROTO, timeout=3600)
    mres = re.findall(r"GRAND TOTAL\s+PASS=(\d+)\s+FAIL=(\d+)", out)
    if mres:
        p, f = int(mres[-1][0]), int(mres[-1][1])
        print("  GRAND TOTAL PASS=%d FAIL=%d" % (p, f))
        return p, f
    print("  could not parse GRAND TOTAL; rc=%d" % rc)
    print(out[-1200:])
    return 0, 1


def run_formal():
    """Run bundled offline verifiers (Tamarin-equivalent, CryptoVerif-equivalent)."""
    print("== Tier B: formal verification (offline, bundled) ==")
    ok = True
    for script, expect in [("e16_offline.py", "S1-S5"),
                           ("e18_offline.py", "Lemmas 1-3")]:
        path = os.path.join(FORMAL, script)
        if not os.path.exists(path):
            print("  %-18s MISSING" % script)
            ok = False
            continue
        rc, out = sh([sys.executable, path], cwd=FORMAL, timeout=900)
        # a verifier run is a pass if: exit 0, no Python error, and the
        # completion banner reports all passed / queries proved.
        # (do NOT match the word "fail" loosely — "fail-closed" appears in prose)
        bad = any(k in out for k in ("Traceback", "AssertionError", "not passed",
                                     "FAILURE", "UNPROVED"))
        banner = ("ALL PASSED" in out) or ("proved" in out.lower())
        passed = (rc == 0) and (not bad) and banner
        ok = ok and passed
        tail = " | ".join(l.strip() for l in out.splitlines()[-4:])
        print("  %-18s %s  (%s)" % (script, "PASS" if passed else "FAIL",
                                    tail or "rc=%d" % rc))
    return ok


def run_eval(quick=True):
    print("== Tier A: evaluation framework (%s) ==" %
          ("--quick" if quick else "--full"))
    path = os.path.join(RESEARCH, "eval_framework.py")
    if not os.path.exists(path):
        print("  eval_framework.py MISSING")
        return False
    flag = "--quick" if quick else "--full"
    rc, out = sh([sys.executable, path, flag], cwd=RESEARCH, timeout=3600)
    print(out[-1500:])
    return rc == 0


def verify_expected():
    """Compare a full core check + formal result to expected_results.json."""
    print("== VERIFY against expected_results.json ==")
    try:
        exp = json.load(open(EXPECTED, encoding="utf-8"))
    except Exception as e:
        print("  cannot read expected_results.json: %s" % e)
        return False
    ok = True
    t0 = exp.get("tier0_core", {})
    # grand_total_fail must be 0
    gtf = t0.get("grand_total_fail")
    if gtf is not None:
        p, f = run_full_check()
        if f != gtf:
            print("  [FAIL] grand_total_fail=%d but got %d" % (gtf, f))
            ok = False
        else:
            print("  [OK]   grand_total_fail=0 (PASS=%d)" % p)
    # formal
    if not run_formal():
        ok = False
    # tier A correctness expectations (E3/E4/E5/E7) are in the paper; the
    # eval framework re-checks them and is authoritative on this host.
    print("  NOTE: timing values are per-host; verify correctness assertions.")
    return ok


def main():
    ap = argparse.ArgumentParser(description="agent-cryptid reproduction")
    ap.add_argument("--check", action="store_true",
                    help="full core self-check (all modules)")
    ap.add_argument("--tier", choices=["A", "B"], help="run tier A/B")
    ap.add_argument("--full", action="store_true",
                    help="full paper-scale eval (with --tier A)")
    ap.add_argument("--verify", action="store_true",
                    help="verify against expected_results.json")
    args = ap.parse_args()

    print("=" * 66)
    print("agent-cryptid reproduction package")
    print("python %s | %s" % (sys.version.split()[0], sys.platform))
    print("=" * 66)
    t0 = time.time()
    all_ok = True

    if args.verify:
        all_ok = verify_expected()
    elif args.check:
        p, f = run_full_check()
        all_ok = (f == 0)
    elif args.tier == "A":
        all_ok = run_eval(quick=not args.full)
    else:
        # default: core subset + formal offline
        p, f = run_core_subset()
        all_ok = (f == 0)
        all_ok = run_formal() and all_ok

    dt = time.time() - t0
    print("=" * 66)
    print("RESULT  %s  (%.1fs)" % ("ALL OK" if all_ok else "FAILURE", dt))
    print("=" * 66)
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
