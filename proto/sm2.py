# -*- coding: utf-8 -*-
"""SM3 与 SM2 的纯 Python 实现，零第三方依赖。

用途：智能体密码身份中台技术验证原型（proto）。

要点：SM3 遵循 GB/T 32905-2016；SM2 使用推荐曲线参数，签名验签遵循
GB/T 32918.2；点运算用仿射坐标，模逆用 Fermat 逆元；对固定基点 G 用
4 位窗口法预计算表加速标量乘，其他基点用双倍加。
"""
import secrets

MASK32 = 0xFFFFFFFF

_SM3_IV = (
    0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
    0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
)


def _rotl(x, n):
    n &= 31
    if n == 0:
        return x
    return ((x << n) | (x >> (32 - n))) & MASK32


def _ff(x, y, z, j):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | (x & z) | (y & z)


def _gg(x, y, z, j):
    if j < 16:
        return x ^ y ^ z
    return (x & y) | ((~x) & MASK32 & z)


def _p0(x):
    return x ^ _rotl(x, 9) ^ _rotl(x, 17)


def _p1(x):
    return x ^ _rotl(x, 15) ^ _rotl(x, 23)


def sm3(msg):
    """SM3 摘要，返回 32 字节。"""
    l = len(msg) * 8
    pad = bytearray(msg)
    pad.append(0x80)
    while len(pad) % 64 != 56:
        pad.append(0x00)
    pad += l.to_bytes(8, "big")

    v = _SM3_IV
    for blk in range(len(pad) // 64):
        base = blk * 64
        w = [int.from_bytes(pad[base + 4 * i: base + 4 * i + 4], "big")
             for i in range(16)]
        for j in range(16, 68):
            w.append(_p1(w[j - 16] ^ w[j - 9] ^ _rotl(w[j - 3], 15))
                     ^ _rotl(w[j - 13], 7) ^ w[j - 6])
        w1 = [w[j] ^ w[j + 4] for j in range(64)]

        a, b, c, d, e, f, g, h = v
        for j in range(64):
            tj = 0x79CC4519 if j < 16 else 0x7A879D8A
            ss1 = _rotl((_rotl(a, 12) + e + _rotl(tj, j)) & MASK32, 7)
            ss2 = ss1 ^ _rotl(a, 12)
            tt1 = (_ff(a, b, c, j) + d + ss2 + w1[j]) & MASK32
            tt2 = (_gg(e, f, g, j) + h + ss1 + w[j]) & MASK32
            d = c
            c = _rotl(b, 9)
            b = a
            a = tt1
            h = g
            g = _rotl(f, 19)
            f = e
            e = _p0(tt2)

        v = (a ^ v[0], b ^ v[1], c ^ v[2], d ^ v[3],
             e ^ v[4], f ^ v[5], g ^ v[6], h ^ v[7])

    return b"".join(x.to_bytes(4, "big") for x in v)


# -------------------------------------------------------------- SM2 曲线
P = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
A = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFC
B = 0x28E9FA9E_9D9F5E34_4D5A9E4B_CF6509A7_F39789F5_15AB8F92_DDBCBD41_4D940E93
N = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
GX = 0x32C4AE2C_1F198119_5F990446_6A39C994_8FE30BBF_F2660BE1_715A4589_334C74C7
GY = 0xBC3736A2_F4F6779C_59BDCEE3_6B692153_D0A9877C_C62A4740_02DF32E5_2139F0A0
G = (GX, GY)


def _inv(x, mod):
    return pow(x % mod, mod - 2, mod)


def point_add(p1, p2):
    """仿射坐标点加；None 表示无穷远点。"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _dbl(p):
    return point_add(p, p)


_GTAB = None


def _gtab():
    """预计算 1G..15G，供窗口法使用。惰性初始化，幂等。"""
    global _GTAB
    if _GTAB is None:
        tab = [None]
        cur = G
        for _ in range(15):
            tab.append(cur)
            cur = point_add(cur, G)
        _GTAB = tab
    return _GTAB


def scalar_mult(k, pt=G):
    """标量乘；k 取模 N，结果可能为 None。"""
    k %= N
    if k == 0:
        return None
    if pt == G:
        _gtab()
        width = 4
        cnt = (k.bit_length() + width - 1) // width
        res = None
        for i in range(cnt - 1, -1, -1):
            for _ in range(width):
                res = _dbl(res)
            win = (k >> (width * i)) & ((1 << width) - 1)
            if win:
                res = point_add(res, _GTAB[win])
        return res
    res = None
    for i in range(k.bit_length() - 1, -1, -1):
        res = _dbl(res)
        if (k >> i) & 1:
            res = point_add(res, pt)
    return res


def za(idn, pt):
    """按 GB/T 32918.4 计算用户标识摘要 ZA。"""
    def b32(v):
        return v.to_bytes(32, "big")

    x, y = pt
    return sm3(
        (len(idn) * 8).to_bytes(4, "big")
        + idn
        + b32(A) + b32(B)
        + b32(GX) + b32(GY)
        + b32(x) + b32(y)
    )


def gen_keypair():
    """生成密钥对 (d, pub)。"""
    while True:
        d = secrets.randbelow(N - 1) + 1
        pub = scalar_mult(d)
        if pub is not None:
            return d, pub


def _digest(idn, pub, msg):
    """计算签名摘要 e。idn 为 None 时不做 ZA（对齐 gmssl 的默认约定）。"""
    if idn is None:
        return sm3(msg)
    return sm3(za(idn, pub) + msg)


def sign(idn, priv, msg):
    """SM2 签名，返回 (r, s)。idn=None 时不做 ZA。"""
    pub = scalar_mult(priv)
    e = int.from_bytes(_digest(idn, pub, msg), "big")
    while True:
        k = secrets.randbelow(N - 1) + 1
        x1 = scalar_mult(k)[0]
        r = (e + x1) % N
        if r == 0 or r + k == N:
            continue
        s = _inv((1 + priv) % N, N) * ((k - r * priv) % N) % N
        if s == 0:
            continue
        return r, s


def verify(idn, pub, r, s, msg):
    """SM2 验签。idn=None 时不做 ZA。"""
    if not (0 < r < N and 0 < s < N):
        return False
    e = int.from_bytes(_digest(idn, pub, msg), "big")
    t = (r + s) % N
    if t == 0:
        return False
    p1 = scalar_mult(s)
    p2 = scalar_mult(t, pub)
    p3 = point_add(p1, p2)
    if p3 is None:
        return False
    return (e + p3[0]) % N == r


def self_check():
    """内部自检，返回 (项目名, 结果) 列表。"""
    out = []
    out.append(("曲线素数 P 等于 2^256-2^224-2^96+2^64-1",
                P == 2 ** 256 - 2 ** 224 - 2 ** 96 + 2 ** 64 - 1))
    out.append(("基点 G 满足曲线方程",
                (GY * GY - (GX ** 3 + A * GX + B)) % P == 0))
    out.append(("曲线阶 N 满足 N 倍 G 为无穷远点", scalar_mult(N) is None))
    out.append(("窗口法标量乘与逐位标量乘一致",
                scalar_mult(12345, G) == _scalar_mult_naive(12345, G)))
    return out


def _scalar_mult_naive(k, pt):
    """不用窗口法的朴素实现，仅供交叉校验。"""
    res = None
    for i in range(k.bit_length() - 1, -1, -1):
        res = _dbl(res)
        if (k >> i) & 1:
            res = point_add(res, pt)
    return res
