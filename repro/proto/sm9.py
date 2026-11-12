# -*- coding: utf-8 -*-
"""SM9 标识密码算法（GB/T 38635 / GM/T 0044）数字签名 —— 纯 Python 零依赖实现。

为什么自研
----------
- 项目要求零第三方依赖 + 国密合规；
- gmssl 3.2.2 无 sm9 模块（已实测确认），pypi 无可用 sm9 包；
- 自研才能把「标识即公钥」真正接进智能体身份体系，而非黑盒调用。

数学结构
--------
- 256 位 BN 曲线，嵌入次数 k = 12，R-ate 双线性对
- 基曲线   E : y^2 = x^3 + 5           over F_q      -> G1
- 扭曲线   E': y^2 = x^3 + 5u          over F_q^2    -> G2  (d=6 twist, beta = u = sqrt(-2))
- 塔式扩张 F_q^2 = F_q[u]/(u^2 + 2)                  -> 本文件用 u^2 = -2
- 签名算法为 Sakai-Kasahara 结构：
    主私钥 s, 主公钥 P_pub = [s]P2 (G2)
    h1 = H1(ID || hid, N)   —— 整数，不是群元素
    t1 = (s + h1) mod N
    t2 = s * t1^{-1} mod N
    用户私钥 ds_A = [t2] P1 (G1)

元素表示约定（重要）
--------------------
F_q^2 元素用二元元组 (a, b) 表示 **a + b*u**，其中 u^2 = -2。
国密标准文档里写作 (c0, c1) 时实际表示 **c1 + c0*u**（即第一个分量是 u 的系数）。
本文件内部统一用 (a, b) = a + b*u，读入标准常量时已做换算，见下方注释。

已通过官方已知答案测试（KAT）
------------------------------
- t1 / t2 / ds_A 派生（GM/T 0044.5 附录 A，ID="Alice"）
- P_pub = [ks]P2（G2）
- 见 self_check()
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402  （复用项目自研 SM3）


# ==================================================================
# 1. 系统参数（GM/T 0044.5，已用 t 做自洽验算：q+1-tr == N）
# ==================================================================
T_PARAM = int('600000000058F98A', 16)
Q = int('B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D', 16)
N = int('B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25', 16)
TR = int('D8000000019062ED0000B98B0CB27659', 16)
B_EQ = 5
CF = 1
K_EMBED = 12
CID = 0x12
EID = 0x04
HID_SIGN = 0x01

# G1 生成元（E over F_q）
P1 = (int('93DE051D62BF718FF5ED0704487D01D6E1E4086909DC3280E8C4E4817C66DDDD', 16),
      int('21FE8DDA4F21E607631065125C395BBC1C1C00CBFA6024350C464CD70A3EA616', 16))

# G2 生成元（E' over F_q^2）
# 标准写法 x_P2 = (85AEF3D0..., 37227552...) 意为 37227552... + 85AEF3D0...*u
# 换算成本文件 (a, b) = a + b*u 约定后：
P2 = (
    (int('3722755292130B08D2AAB97FD34EC120EE265948D19C17ABF9B7213BAF82D65B', 16),
     int('85AEF3D078640C98597B6027B441A01FF1DD2C190F5E93C454806C11D8806141', 16)),
    (int('A7CF28D519BE3DA65F3170153D278FF247EFBA98A71A08116215BBA5C999A7C7', 16),
     int('17509B092E845C1266BA0D262CBEE6ED0736A96FA347C8BD856DC76B84EBEB96', 16)),
)

# 扭曲线常数 b' = 5u，即 (0, 5) 在本文件约定下 = 0 + 5u
B_TWIST = (0, 5)


# ==================================================================
# 2. F_q 基础运算
# ==================================================================
def fq_inv(a):
    return pow(a % Q, Q - 2, Q)


# ==================================================================
# 3. F_q^2 = F_q[u]/(u^2 + 2)，即 u^2 = -2
#    元素 (a, b) 表示 a + b*u
# ==================================================================
FQ2_ZERO = (0, 0)
FQ2_ONE = (1, 0)


def fq2_add(x, y):
    return ((x[0] + y[0]) % Q, (x[1] + y[1]) % Q)


def fq2_sub(x, y):
    return ((x[0] - y[0]) % Q, (x[1] - y[1]) % Q)


def fq2_neg(x):
    return ((-x[0]) % Q, (-x[1]) % Q)


def fq2_mul(x, y):
    """(a+bu)(c+du) = (ac - 2bd) + (ad+bc)u   [u^2 = -2]"""
    a, b = x
    c, d = y
    return ((a * c - 2 * b * d) % Q, (a * d + b * c) % Q)


def fq2_sqr(x):
    a, b = x
    return ((a * a - 2 * b * b) % Q, (2 * a * b) % Q)


def fq2_inv(x):
    """(a+bu)^{-1} = (a - bu)/(a^2 + 2b^2)"""
    a, b = x
    d = fq_inv((a * a + 2 * b * b) % Q)
    return ((a * d) % Q, ((-b) * d) % Q)


def fq2_mul_scalar(x, k):
    return ((x[0] * k) % Q, (x[1] * k) % Q)


def fq2_pow(x, e):
    """平方-乘幂。e 可为大整数。"""
    if e == 0:
        return FQ2_ONE
    if e < 0:
        x, e = fq2_inv(x), -e
    result = FQ2_ONE
    base = x
    while e:
        if e & 1:
            result = fq2_mul(result, base)
        base = fq2_sqr(base)
        e >>= 1
    return result


# ==================================================================
# 4. G1：E(F_q): y^2 = x^3 + 5
# ==================================================================
G1_INF = None


def g1_is_on_curve(p):
    if p is G1_INF:
        return True
    x, y = p
    return (y * y - (x * x * x + B_EQ)) % Q == 0


def g1_add(p1, p2):
    if p1 is G1_INF:
        return p2
    if p2 is G1_INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if (x1 - x2) % Q == 0:
        if (y1 + y2) % Q == 0:
            return G1_INF
        lam = (3 * x1 * x1) * fq_inv((2 * y1) % Q) % Q
    else:
        lam = (y2 - y1) * fq_inv((x2 - x1) % Q) % Q
    x3 = (lam * lam - x1 - x2) % Q
    y3 = (lam * (x1 - x3) - y1) % Q
    return (x3, y3)


def g1_neg(p):
    if p is G1_INF:
        return G1_INF
    return (p[0], (-p[1]) % Q)


def g1_mul(k, p):
    k = k % N
    if k == 0 or p is G1_INF:
        return G1_INF
    result = G1_INF
    addend = p
    while k:
        if k & 1:
            result = g1_add(result, addend)
        addend = g1_add(addend, addend)
        k >>= 1
    return result


# ==================================================================
# 5. G2：E'(F_q^2): y^2 = x^3 + 5u
# ==================================================================
G2_INF = None


def g2_is_on_curve(p):
    if p is G2_INF:
        return True
    x, y = p
    lhs = fq2_sqr(y)
    rhs = fq2_add(fq2_mul(fq2_sqr(x), x), B_TWIST)
    return lhs == rhs


def g2_add(p1, p2):
    if p1 is G2_INF:
        return p2
    if p2 is G2_INF:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    dx = fq2_sub(x2, x1)  # 相异点相加：λ = (y2-y1)/(x2-x1)
    if dx == FQ2_ZERO:
        dy = fq2_add(y1, y2)
        if dy == FQ2_ZERO:
            return G2_INF
        lam = fq2_mul(fq2_mul_scalar(fq2_sqr(x1), 3), fq2_inv(fq2_mul_scalar(y1, 2)))
    else:
        lam = fq2_mul(fq2_sub(y2, y1), fq2_inv(dx))
    x3 = fq2_sub(fq2_sub(fq2_sqr(lam), x1), x2)
    y3 = fq2_sub(fq2_mul(lam, fq2_sub(x1, x3)), y1)
    return (x3, y3)


def g2_neg(p):
    if p is G2_INF:
        return G2_INF
    return (p[0], fq2_neg(p[1]))


def g2_mul(k, p):
    k = k % N
    if k == 0 or p is G2_INF:
        return G2_INF
    result = G2_INF
    addend = p
    while k:
        if k & 1:
            result = g2_add(result, addend)
        addend = g2_add(addend, addend)
        k >>= 1
    return result


# ==================================================================
# 6. 官方已知答案测试（KAT）常量 —— GM/T 0044.5 附录 A
# ==================================================================
KAT_KS = int('0130E78459D78545CB54C587E02CF480CE0B66340F319F348A1D5B1F2DC5F4', 16)
KAT_ID = 'Alice'
KAT_H1 = int('2ACC468C3926B0BDB2767E99FF26E084DE9CED8DBC7D5FBF418027B667862FAB', 16)
KAT_T1 = int('2ACD7773BD808842F841D35F87070D795F6AF8F3F08C915E760A451186B3F59F', 16)
KAT_T2 = int('291FE3CAC8F58AD2DC462C8D4D578A94DAFD5624DDC28E328D2936688A86CF1A', 16)
KAT_DSA = (int('A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820', 16),
           int('78559A844411F9825C109F5EE3F52D720DD01785392A727BB1556952B2B013D3', 16))
KAT_MSG = 'Chinese IBS standard'
KAT_H = int('823C4B21E4BD2DFE1ED92C606653E996668563152FC33F55D7BFBB9BD9705ADB', 16)
KAT_S = (int('73BF96923CE58B6AD0E13E9643A406D8EB98417C50EF1B29CEF9ADB48B6D598C', 16),
         int('856712F1C2E0968AB7769F42A99586AED139D5B8B3E15891827CC2ACED9BAA05', 16))

# P_pub-s = [ks]P2（标准写法 (c0,c1)=c1+c0*u，已换算为本文件约定）
KAT_PPUB = (
    (int('29DBA116152D1F786CE843ED24A3B573414D2177386A92DD8F14D65696EA5E32', 16),
     int('9F64080B3084F733E48AFF4B41B565011CE0711C5E392CFB0AB1B6791B94C408', 16)),
    (int('41E00A53DDA532DA1A7CE027B7A46F741006E85F5CDFF0730E75C05FB4E3216D', 16),
     int('69850938ABEA0112B57329F447E3A0CBAD3E2FDB1A77F335E89E1408D0EF1C25', 16)),
)


# ==================================================================
# 7. 哈希函数 H1 / H2（GB/T 38635 & John-Yu SM9 权威实现）
# ------------------------------------------------------------------
# 算法（gmalg SM9Core._cipher_fn 逐行对齐）:
#     hlen = ceil(5 * log2(N) / 32) = 40    # SM3 输出 32B
#     count, tail = divmod(hlen, 32)         # count=1, tail=8
#     Z = prefix_byte || Z
#     Ha = SM3(Z || ct=1)                     # 32 B
#     Ha = Ha || SM3(Z || ct=2)[:tail]        # +8 B = 40 B
#     h = (int(Ha, 'big') % (N-1)) + 1        # [1, N-1]
# 前缀字节：H1=0x01（身份标识），H2=0x02（消息哈希）
# ==================================================================
import math  # noqa: E402
import secrets  # noqa: E402

_HLEN = math.ceil(5 * math.log2(N) / 32)  # = 40 字节


def _cipher_fn(prefix_byte, Z, hlen=_HLEN):
    """通用哈希函数：H(prefix, Z) -> 整数 in [1, N-1]。"""
    # SM3 输出长度 256 位 = 32 字节
    v = 32
    count, tail = divmod(hlen, v)
    Z_full = prefix_byte + Z

    Ha = bytearray()
    for ct in range(1, count + 1):
        Ha.extend(sm2.sm3(Z_full + ct.to_bytes(4, 'big')))
    if tail > 0:
        ha_tail = sm2.sm3(Z_full + (count + 1).to_bytes(4, 'big'))
        Ha.extend(ha_tail[:tail])

    return (int.from_bytes(Ha, 'big') % (N - 1)) + 1


def H1(Z):
    """H1(Z) = _cipher_fn(0x01, Z) -> 整数 in [1, N-1]。
    SM9 签名约定：Z = ID_bytes || hid(1B)，hid=0x01。"""
    return _cipher_fn(b'\x01', Z)


def H2(Z):
    """H2(Z) = _cipher_fn(0x02, Z) -> 整数 in [1, N-1]。
    SM9 签名约定：Z = M_bytes || gt_bytes(384B)。"""
    return _cipher_fn(b'\x02', Z)


# ==================================================================
# 8. 配对调用与 GT 序列化（依赖 sm9_pairing）
# ------------------------------------------------------------------
# pair(P_g1, P_g2) 返回 Fp12 GT 元素；
# gt_to_bytes(fp12) 输出 384 字节大端，顺序 [C2 | C1 | C0]，与 gmalg 一致。
# ==================================================================
def _pair(P_g1, P_g2):
    """R-ate 配对，输入使用本文件 sm9 约定，内部转 gmalg 约定。"""
    import sm9_pairing as sp
    P_g1_gm = P_g1
    P_g2_gm = ((P_g2[0][1], P_g2[0][0]), (P_g2[1][1], P_g2[1][0]))
    return sp.pair(P_g1_gm, P_g2_gm)


def _gt_to_bytes(fp12_el):
    """GT = Fp12 -> 384 字节大端，顺序 [C2 | C1 | C0]，每 128B = Fp4。"""
    import sm9_pairing as sp
    return sp.gt_to_bytes(fp12_el)


# ==================================================================
# 9. 密钥派生、签名、验签（Sakai-Kasahara 结构）
# ==================================================================
def derive_user_key(ID, ks, hid=HID_SIGN):
    """用户私钥 ds_A = [t2] * P1 (G1)，其中 t2 = ks / (ks + h1)。"""
    ID_bytes = ID.encode('utf-8') if isinstance(ID, str) else ID
    h1 = H1(ID_bytes + bytes([hid]))
    t1 = (ks + h1) % N
    t2 = ks * pow(t1, N - 2, N) % N
    return g1_mul(t2, P1), t1, t2, h1


def _rand_below_n():
    """生成 [1, N-1] 范围随机整数（等概率，抗拒绝偏差）。"""
    # 用 os.urandom 取 32 字节，若 >= N 或 == 0 重采样
    while True:
        v = int.from_bytes(os.urandom(32), 'big')
        if 1 <= v < N:
            return v


def sign(msg, ds_A, ppub=None, P_pub_g2=None):
    """SM9 签名，返回 (h, S)。
    msg: bytes 消息
    ds_A: G1 用户私钥点
    P_pub_g2: G2 主公钥点（若未提供，需调用方传入）"""
    if P_pub_g2 is None:
        raise ValueError("必须提供 P_pub_g2 主公钥（G2 点）")
    msg_bytes = msg if isinstance(msg, bytes) else msg.encode('utf-8')
    # g = e(P1, P_pub) —— GT 生成元
    g = _pair(P1, P_pub_g2)
    r = _rand_below_n()
    w = pow_g_t(g, r)
    w_bytes = _gt_to_bytes(w)
    h = H2(msg_bytes + w_bytes)
    l = (r - h) % N
    S = g1_mul(l, ds_A)
    return h, S


def verify(msg, h, S, ID, ppub, hid=HID_SIGN):
    """SM9 验签：重算 P=[h1]P2 + P_pub，u=e(S,P)，w'=u*g^h，判 H2(M||w') == h。
    ppub: 用户公钥或 (ID, 主公钥 P_pub_g2) 二元组。本实现使用（ID, P_pub_g2）形式，
    在内部完成 [h1]P2 + P_pub 的合并。"""
    if isinstance(ppub, tuple) and len(ppub) == 2 and ID is None:
        ID, P_pub_g2 = ppub
    else:
        ID, P_pub_g2 = ID, ppub
    msg_bytes = msg if isinstance(msg, bytes) else msg.encode('utf-8')
    ID_bytes = ID.encode('utf-8') if isinstance(ID, str) else ID
    h1 = H1(ID_bytes + bytes([hid]))
    # P = [h1] * P2 + P_pub  （都在 G2）
    P_check = g2_add(g2_mul(h1, P2), P_pub_g2)
    # u = e(S, P)  —— 注意配对是 e(G1, G2)，S 在 G1，P 在 G2
    u = _pair(S, P_check)
    # g = e(P1, P_pub)
    g = _pair(P1, P_pub_g2)
    # w' = u * g^h
    w_prime = _g_t_mul(u, g, h)
    h2 = H2(msg_bytes + _gt_to_bytes(w_prime))
    return h2 == h


# GT 域运算（Fp12 群）
def pow_g_t(f12, e):
    """Fp12 群幂运算，e 是整数标量（Z_N 元素）。"""
    import sm9_pairing as sp
    if e == 0:
        return sp.Z12_ONE
    result = sp.Z12_ONE
    base = f12
    e = e % N
    while e:
        if e & 1:
            result = sp.f12_mul(result, base)
        base = sp.f12_mul(base, base)
        e >>= 1
    return result


def _g_t_mul(u, g, h):
    """u * g^h，两个 GT 元素相乘。"""
    import sm9_pairing as sp
    return sp.f12_mul(u, pow_g_t(g, h))


def signature_to_bytes(h, S):
    """签名 -> bytes：h(32B) || 0x04 || S.x(32B) || S.y(32B) = 97 字节。"""
    if S is G1_INF:
        raise ValueError("S 不应为无穷远点")
    return (h.to_bytes(32, 'big')
            + b'\x04'
            + S[0].to_bytes(32, 'big')
            + S[1].to_bytes(32, 'big'))


def signature_from_bytes(data):
    """bytes -> (h, S)。接受 97 字节：h(32) || 0x04 || S.x(32) || S.y(32)。"""
    if len(data) != 97 or data[32] != 0x04:
        raise ValueError("签名格式错误：应为 97 字节，data[32] == 0x04")
    h = int.from_bytes(data[:32], 'big')
    S = (int.from_bytes(data[33:65], 'big'),
         int.from_bytes(data[65:97], 'big'))
    return h, S


def g1_to_bytes(p):
    """G1 点 -> 65 字节非压缩（0x04 || x || y）。"""
    if p is G1_INF:
        raise ValueError("无穷远点不能序列化")
    x, y = p
    return b'\x04' + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def g2_to_bytes(p):
    """G2 点 -> 129 字节非压缩（0x04 || x0(32) || x1(32) || y0(32) || y1(32)）。
    注意：字节顺序为 Fq2 元素的 (a, b) = a + b*u 按 (a, b) 顺序输出，
    即 (常数项, u 系数)，与国标 SM9 常见序列化 (c0, c1) 顺序一致。"""
    if p is G2_INF:
        raise ValueError("无穷远点不能序列化")
    x, y = p
    return (b'\x04'
            + x[0].to_bytes(32, 'big') + x[1].to_bytes(32, 'big')
            + y[0].to_bytes(32, 'big') + y[1].to_bytes(32, 'big'))


# ==================================================================
# 7. 自检（当前只覆盖到 G1/G2 与私钥派生；配对部分待补）
# ==================================================================
def self_check():
    out = []

    # --- 参数自洽 ---
    q_calc = 36 * T_PARAM**4 + 36 * T_PARAM**3 + 24 * T_PARAM**2 + 6 * T_PARAM + 1
    n_calc = 36 * T_PARAM**4 + 36 * T_PARAM**3 + 18 * T_PARAM**2 + 6 * T_PARAM + 1
    tr_calc = 6 * T_PARAM**2 + 1
    out.append(("参数 q 由 t 推算一致", q_calc == Q))
    out.append(("参数 N 由 t 推算一致", n_calc == N))
    out.append(("迹 tr 由 t 推算一致", tr_calc == TR))
    out.append(("cf=1 自检：q + 1 - tr == N", (Q + 1 - TR) == N))

    # --- 生成元在曲线上 ---
    out.append(("P1 在 E: y^2=x^3+5 上", g1_is_on_curve(P1)))
    out.append(("P2 在 E': y^2=x^3+5u 上", g2_is_on_curve(P2)))

    # --- F_q^2 运算 ---
    u = (0, 1)
    out.append(("F_q^2: u^2 == -2", fq2_sqr(u) == ((-2) % Q, 0)))
    a = (12345, 67890)
    out.append(("F_q^2: a * a^-1 == 1", fq2_mul(a, fq2_inv(a)) == FQ2_ONE))
    b = (98765, 4321)
    out.append(("F_q^2: 乘法交换律", fq2_mul(a, b) == fq2_mul(b, a)))
    out.append(("F_q^2: 加法结合律",
                fq2_add(fq2_add(a, b), u) == fq2_add(a, fq2_add(b, u))))

    # --- 群运算 ---
    out.append(("G1: P1 + (-P1) == O",
                g1_add(P1, g1_neg(P1)) is G1_INF))
    out.append(("G1: [N]P1 == O", g1_mul(N, P1) is G1_INF))
    out.append(("G1: [2]P1 == P1+P1", g1_mul(2, P1) == g1_add(P1, P1)))
    out.append(("G2: P2 + (-P2) == O",
                g2_add(P2, g2_neg(P2)) is G2_INF))
    out.append(("G2: [N]P2 == O", g2_mul(N, P2) is G2_INF))
    out.append(("G2: [2]P2 == P2+P2", g2_mul(2, P2) == g2_add(P2, P2)))

    # --- KAT：私钥派生 ---
    t1 = (KAT_KS + KAT_H1) % N
    out.append(("KAT t1 = (ks + h1) mod N", t1 == KAT_T1))
    t2 = KAT_KS * pow(t1, N - 2, N) % N
    out.append(("KAT t2 = ks * t1^-1 mod N", t2 == KAT_T2))
    dsa = g1_mul(t2, P1)
    out.append(("KAT ds_A = [t2]P1", dsa == KAT_DSA))

    # --- KAT：主公钥 ---
    ppub = g2_mul(KAT_KS, P2)
    out.append(("KAT P_pub = [ks]P2", ppub == KAT_PPUB))
    out.append(("KAT P_pub 在扭曲线上", g2_is_on_curve(ppub)))

    # --- H1 权威测试（Bob, hid=3）—— John-Yu SM9 crate 参考 ---
    bob_h1 = H1(b'Bob' + bytes([3]))
    bob_h1_kat = int('9CB1F6288CE0E51043CE72344582FFC301E0A812A7F5F2004B85547A24B82716', 16)
    out.append(("KAT H1(Bob, hid=3)", bob_h1 == bob_h1_kat))

    # --- 端到端签名/验签（自签自验 + 篡改检测） ---
    h_s, S_s = sign(KAT_MSG.encode('utf-8'), KAT_DSA, P_pub_g2=ppub)
    out.append(("SM9 自签自验", verify(KAT_MSG.encode('utf-8'), h_s, S_s, KAT_ID, ppub)))
    out.append(("SM9 篡改消息失败",
                not verify(b'Chinese IBS standard!', h_s, S_s, KAT_ID, ppub)))
    out.append(("SM9 篡改 h 失败",
                not verify(KAT_MSG.encode('utf-8'), (h_s + 1) % N, S_s, KAT_ID, ppub)))
    out.append(("SM9 换 ID 失败",
                not verify(KAT_MSG.encode('utf-8'), h_s, S_s, 'Mallory', ppub)))

    # --- 序列化往返 ---
    sb = signature_to_bytes(h_s, S_s)
    h_r, S_r = signature_from_bytes(sb)
    out.append(("SM9 签名序列化往返", h_r == h_s and S_r == S_s))
    out.append(("SM9 签名字节长度 97", len(sb) == 97))

    return out


def main():
    results = self_check()
    n_pass = sum(1 for _, ok in results if ok)
    n_fail = sum(1 for _, ok in results if not ok)
    lines = []
    for name, ok in results:
        lines.append("%s  %s" % ("PASS" if ok else "FAIL", name))
    lines.append("")
    lines.append("RESULT  PASS=%d  FAIL=%d" % (n_pass, n_fail))
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                               "sm9_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
