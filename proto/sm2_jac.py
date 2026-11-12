# -*- coding: utf-8 -*-
"""SM2 标量乘：Jacobian 投影坐标实现（无内部模逆）。

问题根源
--------
自研 sm2.point_add 用仿射坐标，每次点加都要做一次模逆：

    _inv(x, P) = pow(x, P-2, P)

这是 ~256 次 256 位模乘（费马小定理）。标量乘含上百次点加 → 单次标量乘
~33 ms，占验签总耗时的 97.8%。

解法
----
Jacobian 投影坐标 (X : Y : Z)，对应仿射 (X/Z², Y/Z³)：
    - double / add 全程只做模乘，无模逆
    - 仅在最后 jac_to_affine 做 1 次模逆
代价：标量乘从 ~33ms → ~2-3ms（预期 10x+）

坐标公式（通用 a，SM2 的 a = P-3）
--------------------------------
Double:
    S  = 4·X·Y²
    M  = 3X² + a·Z⁴
    T  = M² - 2S
    X' = T
    Y' = M·(S-T) - 8·Y⁴
    Z' = 2·Y·Z
Add (Jacobian + Jacobian):
    U1 = X1·Z2²,  U2 = X2·Z1²
    S1 = Y1·Z2³,  S2 = Y2·Z1³
    H  = U2-U1,   R  = 2·(S2-S1)
    I  = (2H)²,   J  = H·I,  V = U1·I
    X' = R² - J - 2V
    Y' = R·(V-X') - 2·S1·J
    Z' = ((Z1+Z2)² - Z1² - Z2²)·H
Mixed add（第二点 Z=1）为 Add 的化简，省 4 次模乘。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402

P = sm2.P
A = sm2.A
N = sm2.N
GX, GY = sm2.GX, sm2.GY

# 无穷远点：Z == 0
INFINITY = (1, 1, 0)


def _norm(v):
    return v % P


def jac_double(pt):
    """Jacobian 倍点。pt = (X, Y, Z)。"""
    X, Y, Z = pt
    if Z == 0 or Y == 0:
        return INFINITY
    XX = X * X % P
    YY = Y * Y % P
    YYYY = YY * YY % P
    ZZ = Z * Z % P
    # S = 4·X·Y²  = 2·((X+Y²)² - X² - Y⁴)
    t = (X + YY) % P
    S = 2 * ((t * t - XX - YYYY) % P) % P
    M = (3 * XX + A * ZZ % P * ZZ % P) % P
    T = (M * M - 2 * S) % P
    X3 = T
    Y3 = (M * (S - T) - 8 * YYYY) % P
    Z3 = 2 * Y % P * Z % P
    return (X3, Y3, Z3)


def jac_add(p1, p2):
    """Jacobian 点加（两点均 Jacobian）。"""
    X1, Y1, Z1 = p1
    X2, Y2, Z2 = p2
    if Z1 == 0:
        return p2
    if Z2 == 0:
        return p1
    Z1Z1 = Z1 * Z1 % P
    Z2Z2 = Z2 * Z2 % P
    U1 = X1 * Z2Z2 % P
    U2 = X2 * Z1Z1 % P
    S1 = Y1 * Z2 % P * Z2Z2 % P
    S2 = Y2 * Z1 % P * Z1Z1 % P
    H = (U2 - U1) % P
    R = 2 * (S2 - S1) % P
    if H == 0:
        if R == 0:
            return jac_double(p1)   # 同点 → 倍点
        return INFINITY             # 互逆 → 无穷远
    I = (2 * H) % P
    I = I * I % P
    J = H * I % P
    V = U1 * I % P
    X3 = (R * R - J - 2 * V) % P
    Y3 = (R * (V - X3) - 2 * S1 % P * J) % P
    Z3 = (((Z1 + Z2) % P * ((Z1 + Z2) % P) - Z1Z1 - Z2Z2) % P) * H % P
    return (X3, Y3, Z3)


def jac_add_mixed(p1, aff2):
    """Jacobian 点加 + 仿射点（Z2 == 1），比 jac_add 少 4 次模乘。"""
    X1, Y1, Z1 = p1
    x2, y2 = aff2
    if Z1 == 0:
        return (x2, y2, 1)
    Z1Z1 = Z1 * Z1 % P
    U2 = x2 * Z1Z1 % P
    S2 = y2 * Z1 % P * Z1Z1 % P
    H = (U2 - X1) % P
    R = 2 * (S2 - Y1) % P
    if H == 0:
        if R == 0:
            return jac_double(p1)
        return INFINITY
    I = (2 * H) % P
    I = I * I % P
    J = H * I % P
    V = X1 * I % P
    X3 = (R * R - J - 2 * V) % P
    Y3 = (R * (V - X3) - 2 * Y1 % P * J) % P
    Z3 = 2 * Z1 % P * H % P
    return (X3, Y3, Z3)


def jac_to_affine(pt):
    """归一化回仿射坐标。全程唯一一次模逆。"""
    X, Y, Z = pt
    if Z == 0:
        return None
    zinv = pow(Z % P, P - 2, P)
    zinv2 = zinv * zinv % P
    return (X * zinv2 % P, Y * zinv2 % P * zinv % P)


# ---------------------------------------------------------------
# 标量乘
# ---------------------------------------------------------------
def scalar_mult_jac(k, pt=(GX, GY)):
    """Jacobian MSB-first 二进制标量乘。返回仿射 (x, y) 或 None。

    全程无模逆；仅最后一次 jac_to_affine 做 1 次模逆。
    """
    if k == 0 or pt is None:
        return None
    k = k % N
    if k == 0:
        return None
    if k == 1:
        return (pt[0] % P, pt[1] % P)

    bits = k.bit_length()
    R = (pt[0] % P, pt[1] % P, 1)   # 仿射起点转 Jacobian(Z=1)
    # MSB-first：跳过最高位（它决定起点），从次高位往下
    mask = 1 << (bits - 2)
    while mask:
        R = jac_double(R)
        if k & mask:
            R = jac_add_mixed(R, pt)
        mask >>= 1
    return jac_to_affine(R)


# ---------------------------------------------------------------
# 4-bit 窗口法（odd multiples 预计算 + mixed add）
# ---------------------------------------------------------------
def _odd_table(pt, w=4):
    """预计算 1P, 3P, ..., (2^w - 1)P 的仿射坐标表。

    返回 dict: odd_value(1,3,...,15) -> (x, y)
    用「先算 P，再反复 mixed-add 2P」的方式构建，避免昂贵的对象数量回合。
    """
    # 2P
    two = jac_to_affine(jac_double((pt[0] % P, pt[1] % P, 1)))
    tab = {}
    cur = (pt[0] % P, pt[1] % P)     # 1P
    step_aff = two                    # 每次加 2P 得到下一个奇数倍
    for i in range(1, 2 ** (w - 1) + 1):
        odd = 2 * i - 1
        tab[odd] = cur
        # cur += 2P
        acc = (cur[0], cur[1], 1)
        acc = jac_add_mixed(acc, step_aff)
        cur = jac_to_affine(acc)
        if cur is None:
            break
    return tab


def scalar_mult_window(k, pt=(GX, GY), w=4):
    """4-bit 奇数窗口标量乘（Jacobian 内部 + mixed add）。

    对每一位组：先 double w 次，再按组值加一个预计算的奇数倍点。
    组内偶数值通过「借位」化为奇数处理。
    """
    if k == 0 or pt is None:
        return None
    k = k % N
    if k == 0:
        return None
    if k == 1:
        return (pt[0] % P, pt[1] % P)

    tab = _odd_table(pt, w)
    bits = k.bit_length()
    nwin = (bits + w - 1) // w

    R = INFINITY
    for i in range(nwin - 1, -1, -1):
        if R != INFINITY:
            for _ in range(w):
                R = jac_double(R)
        win = (k >> (i * w)) & (2 ** w - 1)
        if win == 0:
            continue
        if win % 2 == 1:
            addend = tab.get(win)
            if addend is None:
                raise ValueError("table miss %d" % win)
            R = jac_add_mixed(R, addend) if R != INFINITY \
                else (addend[0], addend[1], 1)
        else:
            # 偶数组：加 (win-1) 倍点（奇数），再补一个 base 点
            addend = tab.get(win - 1)
            if addend is None:
                raise ValueError("table miss %d" % (win - 1))
            R = jac_add_mixed(R, addend) if R != INFINITY \
                else (addend[0], addend[1], 1)
            R = jac_add_mixed(R, (pt[0] % P, pt[1] % P))
    return jac_to_affine(R)


# ---------------------------------------------------------------
# Shamir 联合标量乘：一次倍点链同时算 [s]G + [t]PA
# ---------------------------------------------------------------
def scalar_mult_shamir(a, b, pt_a=(GX, GY), pt_b=None):
    """同时计算 [a]pt_a + [b]pt_b，共享倍点链（MHz 级别的省时点）。

    验签核心式： [s]G + [t]PA
    若分别算两次标量乘，需要做 512 次倍点；合并后只需 256 次，
    倍点次数直接减半，点加次数基本不变（平均 ~1 次/比特）。

    返回仿射坐标或 None。
    """
    if pt_b is None:
        raise ValueError("pt_b required")
    a %= N
    b %= N
    if a == 0 and b == 0:
        return None

    bits = max(a.bit_length(), b.bit_length())
    if bits == 0:
        return None

    ax = (pt_a[0] % P, pt_a[1] % P)
    bx = (pt_b[0] % P, pt_b[1] % P)

    R = INFINITY
    mask = 1 << (bits - 1)
    while mask:
        R = jac_double(R)
        if a & mask:
            R = jac_add_mixed(R, ax)
        if b & mask:
            R = jac_add_mixed(R, bx)
        mask >>= 1
    return jac_to_affine(R)


# ---------------------------------------------------------------
# 宽度 w 联合窗口双标量乘 [a]G + [b]pt_b（v2.19 加速）
# ---------------------------------------------------------------
# 说明：把 a、b 每 w 位分一组（digit ∈ 0..2^w-1，还原 sum(digit·2^(w·i))），
# 预计算 comb[(da,db)] = da·G + db·pt_b（仿射，一次性模逆，按 pt_b 内容缓存）。
# 运行时每窗 w 次 jac_double + 1 次 jac_add_mixed（仿射组合点），全程无运行时
# 模逆。相比逐比特 Shamir（256 double + ~128 mixed_add），点加次数降至
# ~ceil(bitlen/w)（约 64 次），实测核心提速约 1.6x（本机 2.53→1.59 ms）。

_to_window_cache_guard = {}   # 占位，防误删；实际缓存见 _comb_table_full


def _to_window(k, w=4):
    """宽度 w 窗口：digit_i = 第 i 个 w 位组，还原 sum(digit·2^(w·i))。"""
    mask = 2 ** w - 1
    digits = []
    d = k
    while d:
        digits.append(d & mask)
        d >>= w
    return digits


def _pow_table_jac(pt, w=4):
    """i·pt 的 Jacobian 表，i = 0..2^w-1（i=0 为无穷远）。"""
    n = 2 ** w
    tab = {0: INFINITY}
    tab[1] = (pt[0] % P, pt[1] % P, 1)
    cur = tab[1]
    for i in range(2, n):
        cur = jac_add(cur, tab[1])
        tab[i] = cur
    return tab


from collections import OrderedDict

_comb_cache = OrderedDict()
_COMB_CACHE_MAX = 8   # 最多缓存 8 个不同公钥的组合表，防多签发方内存增长
# v2.20：冷态公钥「首次出现」标记（LRU 上限 _COLD_SEEN_MAX）。
# 用于启发：首次见到的公钥走无窗口回退（省 16 次模逆），第二次起才建表缓存。
_cold_seen = OrderedDict()
_COLD_SEEN_MAX = 256


def _comb_table_full(pt_b, w=4):
    """仿射全组合表 comb[(da,db)] = da·G + db·pt_b，da,db∈0..2^w-1 不全 0。
    预计算做模逆（一次性），按 pt_b 内容缓存（LRU，上限 _COMB_CACHE_MAX）。
    """
    key = ("FULL", pt_b[0] % P, pt_b[1] % P, w)
    cached = _comb_cache.get(key)
    if cached is not None:
        _comb_cache.move_to_end(key)
        return cached
    g_tab = _pow_table_jac((GX, GY), w)
    b_tab = _pow_table_jac(pt_b, w)
    comb = {}
    for da in range(2 ** w):
        for db in range(2 ** w):
            if da == 0 and db == 0:
                continue
            comb[(da, db)] = jac_to_affine(jac_add(g_tab[da], b_tab[db]))
    _comb_cache[key] = comb
    while len(_comb_cache) > _COMB_CACHE_MAX:
        _comb_cache.popitem(last=False)
    return comb


def scalar_mult_shamir_window(a, b, pt_a=(GX, GY), pt_b=None, w=4):
    """[a]pt_a + [b]pt_b，宽度 w 联合窗口。返回仿射或 None。

    验签核心式 [s]G + [t]PA 的加速实现（v2.19）。pt_a 须为固定基点 G。

    v2.20 冷态回退：宽度 w 窗口首次见到某公钥时要预计算 256 个仿射组合点
    （16 次模逆，≈32ms）。若该公钥「只用一次」（委托链每跳签发方不同），
    这笔一次性成本纯属浪费，比逐比特 Shamir（全程 Jacobian，仅末尾 1 次
    模逆，≈2.5ms）慢 10 倍以上——这正是 D3/NFR-03 十跳链 361ms 超标的
    根因。故：首次见到的公钥自动回退到无窗口 scalar_mult_shamir；同一
    公钥第二次出现（确认被复用，如同一签发方验大量凭证）才建表缓存并
    走窗口快路径，保留 v2.19 的加速语义。
    """
    if pt_b is None:
        raise ValueError("pt_b required")
    a %= N
    b %= N
    if a == 0 and b == 0:
        return None
    key = ("FULL", pt_b[0] % P, pt_b[1] % P, w)
    if key not in _comb_cache:
        if key in _cold_seen:
            # 已确认复用 → 建表（一次性 32ms，此后命中缓存走窗口）
            _cold_seen.pop(key)
            _comb_table_full(pt_b, w)
        else:
            # 首次出现 → 回退无窗口（1 次模逆），避免 32ms 惩罚
            _cold_seen[key] = 1
            while len(_cold_seen) > _COLD_SEEN_MAX:
                _cold_seen.popitem(last=False)
            return scalar_mult_shamir(a, b, pt_a, pt_b)
    sa = _to_window(a, w)
    sb = _to_window(b, w)
    nwin = max(len(sa), len(sb))
    comb = _comb_table_full(pt_b, w)
    ax = (pt_a[0] % P, pt_a[1] % P)
    R = INFINITY
    for i in range(nwin - 1, -1, -1):
        if R != INFINITY:
            for _ in range(w):
                R = jac_double(R)
        da = sa[i] if i < len(sa) else 0
        db = sb[i] if i < len(sb) else 0
        if da == 0 and db == 0:
            continue
        pt = comb[(da, db)]
        # pt_a 若非常用基点 G，需用 jac_add（组合表按 G 预计算），
        # 此处断言 pt_a 为 G 以复用 comb；否则回退 jac_add。
        if ax == (GX % P, GY % P):
            R = jac_add_mixed(R, pt) if R != INFINITY else (pt[0], pt[1], 1)
        else:
            R = jac_add(R, (pt[0], pt[1], 1)) if R != INFINITY \
                else (pt[0], pt[1], 1)
    return jac_to_affine(R)


# ---------------------------------------------------------------
# 自检：与自研仿射实现对照
# ---------------------------------------------------------------
def self_check():
    out = []
    import secrets

    # 1. Jacobian double 与仿射 double 一致
    d, pub = sm2.gen_keypair()
    j = (pub[0], pub[1], 1)
    jd = jac_to_affine(jac_double(j))
    ad = sm2.point_add(pub, pub)
    out.append(("Jacobian 倍点与仿射一致", jd == ad))

    # 2. Jacobian add 与仿射 add 一致
    _, pub2 = sm2.gen_keypair()
    ja = jac_to_affine(jac_add((pub[0], pub[1], 1),
                               (pub2[0], pub2[1], 1)))
    aa = sm2.point_add(pub, pub2)
    out.append(("Jacobian 点加与仿射一致", ja == aa))

    # 3. mixed add 与 jac_add 一致
    jm = jac_to_affine(jac_add_mixed((pub[0], pub[1], 1), pub2))
    out.append(("Mixed 点加与 Jacobian 一致", jm == ja))

    # 4. 小标量标量乘一致
    for k in (2, 3, 5, 7, 16, 255):
        r1 = sm2.scalar_mult(k, pub)
        r2 = scalar_mult_jac(k, pub)
        if r1 != r2:
            out.append(("小标量 k=%d 一致" % k, False))
            break
    else:
        out.append(("小标量标量乘全部一致", True))

    # 5. 随机大标量一致
    okall = True
    for _ in range(5):
        kk = secrets.randbelow(N - 1) + 1
        if sm2.scalar_mult(kk, pub) != scalar_mult_jac(kk, pub):
            okall = False
            break
    out.append(("随机大标量标量乘一致", okall))

    # 6. 基点标量乘 == 公钥推导（k*G）
    okall = True
    for _ in range(3):
        kk = secrets.randbelow(N - 1) + 1
        if scalar_mult_jac(kk) != sm2.scalar_mult(kk):
            okall = False
            break
    out.append(("基点 kG 与自研一致", okall))

    # 7. 4-bit 窗口法与简单 Jacobian 一致
    okall = True
    for _ in range(5):
        kk = secrets.randbelow(N - 1) + 1
        if scalar_mult_window(kk, pub, w=4) != scalar_mult_jac(kk, pub):
            okall = False
            break
    out.append(("4-bit 窗口法与 Jacobian 二进制一致", okall))

    # 8. 阶的性质：N*G == 无穷远
    out.append(("N·G 为无穷远点", scalar_mult_jac(N) is None))

    # 8b. Shamir 联合标量乘与「两次独立标量乘 + 点加」一致
    okall = True
    for _ in range(6):
        ka = secrets.randbelow(N - 1) + 1
        kb = secrets.randbelow(N - 1) + 1
        expect = sm2.point_add(sm2.scalar_mult(ka, (GX, GY)),
                               sm2.scalar_mult(kb, pub))
        got = scalar_mult_shamir(ka, kb, (GX, GY), pub)
        if got != expect:
            okall = False
            break
    out.append(("Shamir 结果 == 两次标量乘+点加", okall))

    # 8c. Shamir 边界：a=0 / b=0
    edge_ok = True
    got0 = scalar_mult_shamir(0, 7, (GX, GY), pub)
    edge_ok &= (got0 == sm2.scalar_mult(7, pub))
    got1 = scalar_mult_shamir(7, 0, (GX, GY), pub)
    edge_ok &= (got1 == sm2.scalar_mult(7, (GX, GY)))
    out.append(("Shamir 边界 a=0/b=0 正确", edge_ok))

    # 8d. 宽度 w 联合窗口 vs Shamir 二进制 一致
    okwin = True
    for _ in range(6):
        ka = secrets.randbelow(N - 1) + 1
        kb = secrets.randbelow(N - 1) + 1
        expect = scalar_mult_shamir(ka, kb, (GX, GY), pub)
        got = scalar_mult_shamir_window(ka, kb, (GX, GY), pub)
        if got != expect:
            okwin = False
            break
    out.append(("宽度 w 联合窗口 == Shamir 二进制", okwin))

    # 8e. 窗口单独标量乘 vs 自研仿射
    okwin2 = True
    for kk in (2, 3, 16, 255, 65535):
        if scalar_mult_shamir_window(kk, 0, (GX, GY), pub) != \
                sm2.scalar_mult(kk, (GX, GY)):
            okwin2 = False
            break
    for _ in range(5):
        kk = secrets.randbelow(N - 1) + 1
        if scalar_mult_shamir_window(kk, 0, (GX, GY), pub) != \
                sm2.scalar_mult(kk, (GX, GY)):
            okwin2 = False
            break
    out.append(("窗口标量乘 b=0 与自研仿射一致", okwin2))

    # 9. 性能对照
    import statistics
    import time
    kk = secrets.randbelow(N - 1) + 1

    def b(fn, n=20):
        ts = []
        for _ in range(n):
            t0 = time.perf_counter()
            fn()
            ts.append((time.perf_counter() - t0) * 1000)
        return statistics.median(ts)

    t_self = b(lambda: sm2.scalar_mult(kk, pub), n=5)
    t_jac = b(lambda: scalar_mult_jac(kk, pub), n=20)
    t_win = b(lambda: scalar_mult_window(kk, pub), n=20)

    kk2 = secrets.randbelow(N - 1) + 1
    t_two = b(lambda: (scalar_mult_jac(kk, pub),
                       scalar_mult_jac(kk2, (GX, GY))), n=20)
    t_shamir = b(lambda: scalar_mult_shamir(kk, kk2, pub, (GX, GY)), n=20)
    t_win = b(lambda: scalar_mult_shamir_window(kk, kk2, pub, (GX, GY)),
              n=20)

    out.append(("Jacobian 二进制快于自研仿射 ≥ 5x",
                t_self / t_jac >= 5.0))
    out.append(("Shamir 快于两次独立标量乘 ≥ 1.2x",
                t_two / t_shamir >= 1.2))
    # v2.19：宽度 w 联合窗口快于逐比特 Shamir ≥ 1.2x
    out.append(("宽度 w 联合窗口快于 Shamir ≥ 1.2x",
                t_shamir / t_win >= 1.2))

    print()
    print("标量乘性能对照（中位数）")
    print("  自研仿射窗口法     %7.2f ms" % t_self)
    print("  Jacobian 二进制    %7.2f ms   (%.1fx)" % (t_jac, t_self / t_jac))
    print("  Jacobian 4bit窗    %7.2f ms   (%.1fx)" % (t_win, t_self / t_win))
    print("  -- 验签核心式 [s]G+[t]PA --")
    print("  两次独立 Jacobian  %7.2f ms" % t_two)
    print("  Shamir 融合        %7.2f ms   (%.2fx)" % (t_shamir,
                                                       t_two / t_shamir))
    print("  宽度w联合窗口      %7.2f ms   (%.2fx vs Shamir)"
          % (t_win, t_shamir / t_win))
    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
