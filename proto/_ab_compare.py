# -*- coding: utf-8 -*-
"""A/B 对比：同一负载下，旧 Shamir 完整验签 vs 新宽度 w 联合窗口完整验签。

证明优化带来净收益（排除负载因素），并给出优化后 P99 相对余量。
不追求安静机绝对达标（VM 暂不可达），只做同条件 A/B。
"""
import sys
import os
import time
import statistics

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2
from sm2_jac import scalar_mult_shamir, scalar_mult_shamir_window

N = sm2.N


def _bench(fn, n=200, warmup=30):
    for _ in range(warmup):
        fn()
    ts = []
    for _ in range(n):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    med = ts[n // 2]
    p95 = ts[int(n * 0.95) - 1]
    p99 = ts[int(n * 0.99) - 1]
    return med, p95, p99, ts


def main():
    d, pub = sm2.gen_keypair()
    # 完整验签路径（含 ZA + SM3 + 双标量乘）
    idn = b"agent://ab/test"
    msg = b"A/B compare message for NFR-02 margin verification"
    e = int.from_bytes(sm2.za(idn, pub), "big")
    # 用固定 r,s 测验签核心（含 ZA 计算，模拟真实 cold）
    r = 12345678901234567890
    s = 98765432109876543210 % N
    if not (0 < r < N and 0 < s < N):
        s = N - 2
    t = (r + s) % N

    # 旧：逐比特 Shamir（含 ZA 每次重算）
    def old_verify():
        ee = int.from_bytes(sm2.sm3(sm2.za(idn, pub) + msg), "big")
        p3 = scalar_mult_shamir(s, t, pt_b=pub)
        return p3 is not None and (ee + p3[0]) % N == r

    # 新：宽度 w 联合窗口（含 ZA 每次重算，cold 态）
    def new_verify():
        ee = int.from_bytes(sm2.sm3(sm2.za(idn, pub) + msg), "big")
        p3 = scalar_mult_shamir_window(s, t, pt_b=pub)
        return p3 is not None and (ee + p3[0]) % N == r

    print("=== A/B 完整验签（含 ZA+SM3，同负载，cold 态） ===")
    m_old, p95_old, p99_old, _ = _bench(old_verify)
    m_new, p95_new, p99_new, _ = _bench(new_verify)
    print("  旧 Shamir 逐比特  中位 %6.2f  P95 %6.2f  P99 %6.2f ms"
          % (m_old, p95_old, p99_old))
    print("  新 宽度w联合窗口  中位 %6.2f  P95 %6.2f  P99 %6.2f ms"
          % (m_new, p95_new, p99_new))
    print("  提速             中位 %.2fx  P99 %.2fx"
          % (m_old / m_new, p99_old / p99_new))
    print("  新 P99 vs 5ms 上限余量: %.1f%%"
          % ((5.0 - p99_new) / 5.0 * 100))


if __name__ == "__main__":
    main()
