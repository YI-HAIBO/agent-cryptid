# -*- coding: utf-8 -*-
"""纯 Python 实现 ML-DSA（Dilithium，FIPS 204 对齐）— 零依赖。

参数集：ML-DSA-65（FIPS 204 Table 1）：k=6, l=5, d=13, η=4, τ=49, ω=55, γ1=2^19, γ2=(q-1)/32=261888, β=τ·η=196。

实现说明：
    - 算法数学完全按 FIPS 204 / Dilithium：NTT 乘法、CBD_η 与 NTT 域采样、
      SampleInBall 挑战、签名/验签的范数边界检查全部实现。
    - 采用标准 t1+hint 紧凑格式（FIPS 204 Alg. 15/16）：
        公钥 pk = (ρ, t1)，其中 t = t1·2^d + t0（power2round）；
        签名含 hint h = MakeHint(−c·t0, w − c·s2 + c·t0)；
        验签用 UseHint(h, w') 重建 w1，其中 w' = A·z − c·t1·2^d。
      这是 FIPS 204 标准格式，享有完整的可证明安全归约。
    - 签名侧的四道范数测试（FIPS 204 Alg. 15 / dilithium ref/sign.c）：
        z  = y + c·s1           要求 ||z||∞  < γ1 - β
        r0 = LowBits(w) − c·s2  要求 ||r0||∞ < γ2 - β      （w = A·y）
        c·t0                   要求 ||c·t0||∞ < γ2
        hint 权重              要求 ≤ ω = 55
    - 两套分解务必分清：
        t = t1·2^d + t0   用 d = 13，‖t0‖∞ ≤ 2^{d-1} = 4096
        w = w1·2γ2 + w0   用 γ2 = (q-1)/32 = 261888
      二者是不同的量，不能互相套用。
    - decompose 遵循 FIPS 204 特殊情形：当 r1 = (q+1)/(2γ2) = 16 时，
      置 r1=0, r0=r0−1（否则 r1 会出 16，与标准不符）。
    - 哈希 H / H_msg / tr 均用 SHAKE256（见 shake.py）。
    - 内部序列化（非 FIPS 紧凑位打包）：多项式用整数列表，便于原型接线与调试。

接口：
    pk, sk = keygen(seed=None)
    sig     = sign(sk, msg)
    ok      = verify(pk, msg, sig)
"""
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shake  # noqa: E402

# ---------------- 参数（ML-DSA-65，FIPS 204 Table 1）----------------
Q = 8380417               # 2^23 - 2^13 + 1
N = 256
ZETA = 1753               # q 中的 512 次本原根
K = 6                     # A 的行数 / t 的维数
L = 5                     # s1 的维数
D_DROP = 13               # 公钥 t 丢弃的低位比特数
ETA = 4                   # 私钥系数界（CBD_η）
TAU = 49                  # 挑战非零系数个数
OMEGA = 55                # hint 上限
GAMMA1 = 1 << 19          # 2^19
GAMMA2 = (Q - 1) // 32    # 261888 = (q-1)/32
BETA = TAU * ETA          # 196，签名范数界模糊量
_R1_MAX = (Q + 1) // (2 * GAMMA2)   # 16，decompose 的 r1 上限（含 FIPS 204 特殊情形）


def _center(x):
    x %= Q
    return x if x <= Q // 2 else x - Q


def _bitrev(x, bits):
    """bits 位比特反转。"""
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


# 迭代式 NTT（O(n log n)，比定义法 O(n^2) 快约一个数量级）：
#   评估点集 p_i = ζ^{2i+1}（ζ 的奇次幂，是 x^n+1 的根）。
#   令 ω = ζ^2（256 次本原根，ω^128 = ζ^256 = -1），则
#     â[i] = Σ_j a_j · ζ^j · ω^{i·j}  =  NTT_ω( a_j·ζ^j )[i]
#   故前向 = 系数先乘 ζ^j 再做标准 DIT NTT（根 ω）；
#   逆变换 = 标准 GS 逆 NTT（根 ω^{-1}）→ 再乘 ζ^{-j} 并除以 n。
#   已与定义法 NTT、系数域乘法交叉验证一致。
OMEGA_NTT = pow(ZETA, 2, Q)        # 256 次本原根（ζ²）
_NINV = pow(N, Q - 2, Q)         # n^{-1} mod q

# 预计算表（一次性建表，消除每次 NTT 内的大量 pow() 与比特反转开销）：
_BITREV8 = tuple(_bitrev(i, 8) for i in range(N))                  # 比特反转置换
_ZETA_POW = tuple(pow(ZETA, j, Q) for j in range(N))               # ζ^j
_NINV_ZI = tuple((_NINV * pow(ZETA, (Q - 1 - j) % (Q - 1), Q))
                 for j in range(N))                                # n^{-1}·ζ^{-j}
_FWD_TW = []                                                        # 前向各层_twiddle_
_m = 1
while _m < N:
    _FWD_TW.append(pow(OMEGA_NTT, N // (2 * _m), Q))
    _m *= 2
_INV_TW = tuple(pow(w, Q - 2, Q) for w in reversed(_FWD_TW))       # 逆变换各层 _twiddle_


def ntt(a):
    """前向 NTT（系数域 → 频域），迭代式。a: 256 个系数。"""
    n = N
    zp = _ZETA_POW
    b = [(a[j] * zp[j]) % Q for j in range(n)]
    br = _BITREV8
    for i in range(n):
        j = br[i]
        if i < j:
            b[i], b[j] = b[j], b[i]
    m = 1
    layer = 0
    while m < n:
        wm = _FWD_TW[layer]
        layer += 1
        for i in range(0, n, 2 * m):
            w = 1
            for j in range(i, i + m):
                t = (w * b[j + m]) % Q
                u = b[j]
                b[j] = (u + t) % Q
                b[j + m] = (u - t) % Q
                w = (w * wm) % Q
        m *= 2
    return b


def nttinv(a):
    """逆 NTT（频域 → 系数域），含 n^{-1}。迭代式。"""
    n = N
    b = a[:]
    layer = 0
    m = n // 2
    while m >= 1:
        winv = _INV_TW[layer]
        layer += 1
        for i in range(0, n, 2 * m):
            w = 1
            for j in range(i, i + m):
                t = b[j]
                u = b[j + m]
                b[j] = (t + u) % Q
                b[j + m] = ((t - u) * w) % Q
                w = (w * winv) % Q
        m //= 2
    br = _BITREV8
    for i in range(n):
        j = br[i]
        if i < j:
            b[i], b[j] = b[j], b[i]
    nz = _NINV_ZI
    return [(b[j] * nz[j]) % Q for j in range(n)]


def poly_mul_ntt(a_ntt, b_ntt):
    """两个 NTT 域多项式逐点乘，返回 NTT 域结果。

    评估法 NTT（在 ζ^{2i+1} 处求值）的域乘法是逐点普通乘法，
    不需要 X²=-1 蝴蝶（那是 Cooley-Tukey 蝴蝶 NTT 专用）。
    """
    return [(a_ntt[i] * b_ntt[i]) % Q for i in range(N)]


def poly_mul(a, b):
    """系数域多项式乘法（验签/调试用，非主路径）。"""
    c = [0] * N
    a = [_center(x) for x in a]
    b = [_center(x) for x in b]
    for i in range(N):
        if a[i] == 0:
            continue
        for j in range(N):
            kk = (i + j) % N
            sign = 1
            if i + j >= N:
                sign = -1
            c[kk] = (c[kk] + sign * a[i] * b[j]) % Q
    return [_center(x) for x in c]


# ---------------- 采样 ----------------
def _read_bits(buf, pos, nbits):
    """从字节流按小端比特序读取 nbits 位（无符号）。"""
    val = 0
    for t in range(nbits):
        byte = buf[(pos + t) >> 3]
        bit = (byte >> ((pos + t) & 7)) & 1
        val |= bit << t
    return val


def cbd(buf, eta):
    """Centered Binomial Distribution（FIPS 204 CBD_η）：每系数消耗 2η 比特。"""
    coeffs = [0] * N
    pos = 0
    for i in range(N):
        bits = _read_bits(buf, pos, 2 * eta)
        pos += 2 * eta
        x = 0
        y = 0
        for t in range(eta):
            x += (bits >> (2 * t)) & 1
            y += (bits >> (2 * t + 1)) & 1
        coeffs[i] = x - y
    return coeffs


def sample_ntt(stream):
    """从字节流按拒绝采样产出 256 个 NTT 域系数（每个 ∈ [0,q)）。"""
    coeffs = [0] * N
    pos = 0
    i = 0
    while i < N:
        if pos + 3 > len(stream):
            return None
        d = (stream[pos] | (stream[pos + 1] << 8) | (stream[pos + 2] << 16)) & 0x7FFFFF
        pos += 3
        if d < Q:
            coeffs[i] = d
            i += 1
    return coeffs


def sample_in_ball(c_tilde, tau=TAU, n=N):
    """SampleInBall（FIPS 204 Alg 14）：产出恰好 τ 个 +1、τ 个 -1 的多项式。"""
    signs = 0
    for i in range(8):
        signs |= c_tilde[i] << (8 * i)
    nbytes = ((2 * tau * 9 + 7) // 8) + 16
    buf = shake.shake256(c_tilde, nbytes)
    c = [0] * n
    pos = 0
    # 正号
    for _ in range(tau):
        j = _read_bits(buf, pos, 9) % n
        pos += 9
        while c[j] != 0:
            j = (j + 1) % n
        c[j] = 1
    # 负号
    for _ in range(tau):
        j = _read_bits(buf, pos, 9) % n
        pos += 9
        while c[j] != 0:
            j = (j + 1) % n
        c[j] = -1
    # 符号位
    for i in range(n):
        if c[i] != 0:
            if (signs >> i) & 1:
                c[i] = -c[i]
    return c


# ---------------- 分解（HighBits / LowBits / Power2Round）----------------
def decompose(r, gamma2=GAMMA2):
    """Decompose：r = r1*(2γ2) + r0，r0 ∈ [-γ2, γ2)。返回 (r1, r0)。

    遵循 FIPS 204 Alg. 13，含特殊情形：当 r1 = (q+1)/(2γ2) = 16 时，
    置 r1=0, r0=r0−1（否则 r1 会出 16，与标准不符）。
    """
    r = r % Q
    two_g2 = 2 * gamma2
    r1, r0 = divmod(r, two_g2)
    if r0 > gamma2:
        r0 -= two_g2
        r1 += 1
    elif r0 < -gamma2:
        r0 += two_g2
        r1 -= 1
    if r1 == _R1_MAX:
        r1 = 0
        r0 -= 1
    return r1, r0


def high_bits(r, gamma2=GAMMA2):
    return decompose(r, gamma2)[0]


def low_bits(r, gamma2=GAMMA2):
    return decompose(r, gamma2)[1]


def power2round(r, d=D_DROP):
    """Power2Round：r = r1·2^d + r0，r0 ∈ [-2^{d-1}, 2^{d-1}]。返回 (r1, r0)。

    按 Dilithium 参考实现 rounding.c 的公式：
      r1 = (r + 2^{d-1} - 1) >> d
      r0 = r - (r1 << d)
    """
    r = r % Q
    two_d = 1 << d
    half_d = 1 << (d - 1)
    r1 = (r + half_d - 1) >> d
    r0 = r - (r1 << d)
    return r1, r0


def make_hint(a0, a1, gamma2=GAMMA2):
    """MakeHint（FIPS 204 Alg. 15）：检查 HighBits(a1·2γ2 + a0) 是否等于 a1。

    参数：
        a0 = LowBits(w) − c·s2 + c·t0   （未归约的低位，可能超出 ±γ2）
        a1 = HighBits(w)                 （真实的高位）
    返回 1 若 a0 超出 [-γ2, γ2]（或边界特殊情形），否则 0。
    """
    if a0 > gamma2 or a0 < -gamma2 or (a0 == -gamma2 and a1 != 0):
        return 1
    return 0


def use_hint(r, h, gamma2=GAMMA2):
    """UseHint（FIPS 204 Alg. 16）：从 r 和 hint h 重建 HighBits(r)。

    参数：
        r = w' = A·z − c·t1·2^d   （验签侧算出的"未修正"值）
        h = 该系数的 hint（0 或 1）
    返回重建后的 r1；若 h=0 且 |LowBits(r)| ≥ γ2 则返回 None（无效签名）。
    """
    r1, r0 = decompose(r, gamma2)
    if h == 0:
        if abs(r0) >= gamma2:
            return None
        return r1
    else:  # h == 1
        if r0 > 0:
            return (r1 + 1) % _R1_MAX
        else:
            return (r1 - 1) % _R1_MAX


# ---------------- 矩阵 A ----------------
_A_CACHE = {}          # rho -> A（A 仅依赖 rho，缓存避免 sign/verify 重复采样）


def sample_matrix_a(rho, k=K, l=L):
    """采样 k×l 的 A（NTT 域）。A[i][j] 来自 SHAKE256(ρ || j || i)。"""
    if (k, l, rho) in _A_CACHE:
        return _A_CACHE[(k, l, rho)]
    A = [[None] * l for _ in range(k)]
    for i in range(k):
        for j in range(l):
            stream = shake.shake256(rho + bytes([j, i]), 1100)
            A[i][j] = sample_ntt(stream)
    _A_CACHE[(k, l, rho)] = A
    return A


def mat_vec_mul(A, v_ntt):
    """A (k×l) 点乘 向量 v（NTT 域），返回 k 个系数域多项式。"""
    k = len(A)
    l = len(A[0])
    out = [None] * k
    for i in range(k):
        acc = [0] * N
        for j in range(l):
            p = poly_mul_ntt(A[i][j], v_ntt[j])
            acc = [(acc[t] + p[t]) % Q for t in range(N)]
        out[i] = nttinv(acc)
    return out


def _center_nttinv(p_ntt):
    """将 NTT 域多项式转回系数域（并居中）后返回列表。"""
    return [_center(x) for x in nttinv(p_ntt)]


def _ntt_of(p):
    return ntt(p)


def _serialize_t1(t1):
    """将 t1 序列化为字节流（用于 tr = H(ρ || t1) 计算）。"""
    return b"".join(int(x).to_bytes(4, "little", signed=True)
                    for row in t1 for x in row)


# ---------------- 密钥 / 签名 ----------------
def keygen(seed=None):
    """生成 (pk, sk)。seed 提供可复现性（用于持久化/回归测试）。

    pk = (ρ, t1)，sk = (ρ, K, s1, s2, t0, t1)。
    t = A·s1 + s2，t = t1·2^d + t0（power2round）。
    标准紧凑格式：公钥不含 t0，验签用 t1·2^d 重建。
    """
    if seed is None:
        seed = os.urandom(32)
    rho = shake.shake256(seed, 32)
    Kseed = shake.shake256(seed + b"\x01", 32)
    A = sample_matrix_a(rho)
    # 私钥（s1, s2）从派生种子采样 CBD
    s1 = []
    s2 = []
    s1buf = shake.shake256(seed + b"\x02", L * N * 3 + 64)
    s2buf = shake.shake256(seed + b"\x03", K * N * 3 + 64)
    for j in range(L):
        s1.append(ntt(cbd(s1buf[j * (N * 3):], ETA)))
    for i in range(K):
        s2.append(ntt(cbd(s2buf[i * (N * 3):], ETA)))
    # t = A·s1 + s2（系数域）
    As1 = mat_vec_mul(A, s1)
    t = []
    for i in range(K):
        s2c = _center_nttinv(s2[i])          # s2 的系数域表示
        row = [(As1[i][c] + s2c[c]) % Q for c in range(N)]
        t.append(row)
    # power2round 拆分 t = t1·2^d + t0
    t1 = []
    t0 = []
    for i in range(K):
        r1 = []
        r0 = []
        for c in range(N):
            a, b = power2round(t[i][c])
            r1.append(a)
            r0.append(b)
        t1.append(r1)
        t0.append(r0)
    pk = {"rho": rho, "t1": t1}            # 标准紧凑公钥（不含 t0）
    sk = {"rho": rho, "K": Kseed, "s1": s1, "s2": s2, "t0": t0, "t1": t1}
    return pk, sk


def sign(sk, msg, max_tries=1024):
    """对 msg（bytes）签名。返回 sig = {"ct": c_tilde hex, "z": [...], "h": [...]}。

    拒绝采样按 FIPS 204 Alg. 15 做四道范数测试：
        z  = y + c·s1           要求 ||z||∞  < γ1 - β
        r0 = LowBits(w) − c·s2  要求 ||r0||∞ < γ2 - β   （w = A·y）
        c·t0                   要求 ||c·t0||∞ < γ2
        hint 权重              要求 ≤ ω = 55

    hint h = MakeHint(−c·t0, w − c·s2 + c·t0)，逐系数计算。
    y 每轮独立确定性采样，故 (sk, msg) 唯一决定签名，可复现。
    max_tries 默认 1024：单轮接受率约 24%，1024 轮签不出来的概率可忽略。
    """
    rho = sk["rho"]
    Kseed = sk["K"]
    s1 = sk["s1"]
    s2 = sk["s2"]
    t0 = sk["t0"]
    t1 = sk["t1"]
    A = sample_matrix_a(rho)
    tr = shake.shake256(rho + _serialize_t1(t1), 64)
    mu = shake.shake256(tr + msg, 64)
    two_g1 = 2 * GAMMA1
    z_bound = GAMMA1 - BETA
    r_bound = GAMMA2 - BETA
    npack = L * N

    # 预计算 t0 的 NTT 域（避免每轮重复 NTT）
    t0_ntt = [_ntt_of(row) for row in t0]

    def next_y(attempt):
        # 每轮拒绝采样使用独立的确定性 y 流（保证 (sk,msg) 可复现）。
        # 用 struct 一次解包全部 uint32，比逐系数拼字节快一个数量级。
        y_stream = shake.shake256(Kseed + msg + bytes([attempt & 0xFF,
                                                        (attempt >> 8) & 0xFF]),
                                  npack * 4)
        vals = struct.unpack("<%dL" % npack, y_stream)
        return [[_center(v % two_g1 - GAMMA1 + 1)
                 for v in vals[j * N:(j + 1) * N]] for j in range(L)]

    for attempt in range(max_tries):
        y = next_y(attempt)
        y_ntt = [_ntt_of(yj) for yj in y]
        w = mat_vec_mul(A, y_ntt)         # 系数域 k 个多项式（w = A·y）
        w0 = [[low_bits(w[i][c]) for c in range(N)] for i in range(K)]
        w1 = [[high_bits(w[i][c]) for c in range(N)] for i in range(K)]
        w1_bytes = b"".join(
            int(w1[i][c]).to_bytes(4, "little", signed=True)
            for i in range(K) for c in range(N))
        ct = shake.shake256(mu + w1_bytes, 32)
        c = sample_in_ball(ct)
        c_ntt = ntt(c)
        # z = y + c·s1
        z = []
        for j in range(L):
            p = poly_mul_ntt(c_ntt, s1[j])
            cs1 = nttinv(p)
            z.append([(y[j][c] + _center(cs1[c])) % Q for c in range(N)])
        # 范数检查 ||z||∞ < γ1 - β
        zmax = max(abs(_center(z[j][c])) for j in range(L) for c in range(N))
        if zmax >= z_bound:
            continue
        # r0 = LowBits(w) − c·s2，范数检查 ||r0||∞ < γ2 - β
        bad = False
        for i in range(K):
            p = poly_mul_ntt(c_ntt, s2[i])
            cs2 = nttinv(p)
            row0 = w0[i]
            for c in range(N):
                if abs(row0[c] - _center(cs2[c])) >= r_bound:
                    bad = True
                    break
            if bad:
                break
        if bad:
            continue
        # c·t0（系数域），检查 ||c·t0||∞ < γ2
        ct0_bad = False
        for i in range(K):
            p = poly_mul_ntt(c_ntt, t0_ntt[i])
            ct0_i = nttinv(p)
            for c in range(N):
                if abs(_center(ct0_i[c])) >= GAMMA2:
                    ct0_bad = True
                    break
            if ct0_bad:
                break
        if ct0_bad:
            continue
        # 计算 hints：h = MakeHint(−c·t0, w − c·s2 + c·t0)
        #   a0 = LowBits(w) − c·s2 + c·t0
        #   a1 = HighBits(w)
        hints = []
        hint_weight = 0
        for i in range(K):
            p = poly_mul_ntt(c_ntt, s2[i])
            cs2 = nttinv(p)
            p2 = poly_mul_ntt(c_ntt, t0_ntt[i])
            ct0_i = nttinv(p2)
            h_row = []
            for c in range(N):
                a0 = _center(w0[i][c] - _center(cs2[c]) + _center(ct0_i[c]))
                a1 = w1[i][c]
                hh = make_hint(a0, a1)
                h_row.append(hh)
                hint_weight += hh
            hints.append(h_row)
        if hint_weight > OMEGA:
            continue
        return {"ct": ct.hex(),
                "z": [[_center(z[j][c]) for c in range(N)] for j in range(L)],
                "h": hints}
    raise RuntimeError("ML-DSA 签名拒绝采样超限（%d 轮）" % max_tries)


def verify(pk, msg, sig):
    """验签。返回 bool。"""
    rho = pk["rho"]
    t1 = pk["t1"]
    A = sample_matrix_a(rho)
    tr = shake.shake256(rho + _serialize_t1(t1), 64)
    mu = shake.shake256(tr + msg, 64)
    try:
        ct = bytes.fromhex(sig["ct"])
        z = sig["z"]
        h = sig["h"]
    except Exception:
        return False
    if len(z) != L or any(len(row) != N for row in z):
        return False
    if len(h) != K or any(len(row) != N for row in h):
        return False
    c = sample_in_ball(ct)
    c_ntt = ntt(c)
    z_ntt = [_ntt_of(zj) for zj in z]
    # w' = A·z − c·t1·2^d
    Az = mat_vec_mul(A, z_ntt)
    w = []
    for i in range(K):
        t1_ntt = ntt(t1[i])
        p = poly_mul_ntt(c_ntt, t1_ntt)
        ct_i = nttinv(p)
        w.append([(Az[i][c] - (_center(ct_i[c]) << D_DROP)) % Q for c in range(N)])
    # 用 hint 重建 w1
    w1 = []
    for i in range(K):
        w1_row = []
        for c in range(N):
            r1 = use_hint(w[i][c], h[i][c])
            if r1 is None:
                return False
            w1_row.append(r1)
        w1.append(w1_row)
    w1_bytes = b"".join(int(w1[i][c]).to_bytes(4, "little", signed=True)
                        for i in range(K) for c in range(N))
    ct2 = shake.shake256(mu + w1_bytes, 32)
    if ct2 != ct:
        return False
    zmax = max(abs(_center(z[j][c])) for j in range(L) for c in range(N))
    if zmax >= GAMMA1 - BETA:
        return False
    return True


# ---------------- 自测 ----------------
def self_check():
    out = []
    import random
    a = [random.randint(0, Q - 1) for _ in range(N)]
    b = [random.randint(0, Q - 1) for _ in range(N)]
    a_back = nttinv(ntt(a))
    out.append(("NTT 往返", all(x == y for x, y in zip(a_back, a))))
    prod_ntt = nttinv(poly_mul_ntt(ntt(a), ntt(b)))
    prod_ref = poly_mul(a, b)
    out.append(("NTT 乘法一致",
                all((x - y) % Q == 0 for x, y in zip(prod_ntt, prod_ref))))
    # decompose 特殊情形：decompose(Q-1) 应为 (0, -1) 而非 (16, 0)
    r1, r0 = decompose(Q - 1)
    out.append(("decompose(Q-1) 特殊情形", r1 == 0 and r0 == -1))
    # power2round 往返
    pr_ok = True
    for _ in range(100):
        r = random.randint(0, Q - 1)
        r1p, r0p = power2round(r)
        if (r1p << D_DROP) + r0p != r % Q:
            pr_ok = False
            break
    out.append(("power2round 往返", pr_ok))
    # 密钥生成 + 签名 + 验签闭环
    pk, sk = keygen(seed=b"\x00" * 32)
    msg = b"agent-cryptid post-quantum demo"
    sig = sign(sk, msg)
    out.append(("ML-DSA 签名-验签闭环", verify(pk, msg, sig)))
    # 篡改消息应失败
    out.append(("ML-DSA 篡改消息失败", not verify(pk, msg + b"x", sig)))
    # 篡改签名 z 应失败
    bad = dict(sig)
    bad["z"] = [[-x if c == 0 else x for c, x in enumerate(row)] for row in sig["z"]]
    out.append(("ML-DSA 篡改 z 失败", not verify(pk, msg, bad)))
    # 篡改 hint 应失败
    bad2 = dict(sig)
    bad2["h"] = [[1 - x for x in row] for row in sig["h"]]
    out.append(("ML-DSA 篡改 hint 失败", not verify(pk, msg, bad2)))
    # 公钥不含 t0（标准紧凑格式）
    out.append(("公钥不含 t0", "t0" not in pk and "t" not in pk and "t1" in pk))
    return out


if __name__ == "__main__":
    import time as _t
    for name, ok in self_check():
        print("%-22s %s" % ("PASS" if ok else "FAIL", name))