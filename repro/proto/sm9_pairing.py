# -*- coding: utf-8 -*-
"""SM9 R-ate 双线性对 —— 移植自纯 Python 实现 gmalg（ww-rm/gmalg），零依赖。

仅用于 SM9 签名/验签中的配对计算 e: G1 x G2 -> GT (GT c F_q^12)。
Fp2 = Fp[u]/(u^2+2)；Fp4 = Fp2[v]/(v^2-1)（gmalg 塔式表示）；Fp12 = Fp4[w]/(w^3-v)。
曲线: E(Fp): y^2 = x^3 + 5 ; E'(Fp2): y^2 = x^3 + 5 (gmalg 约定的 twist，经 _phi 映射到 E(Fp12))。

注意约定差异: 本文件的 Fp2 元素表示为 (X1, X0) = X0 + X1*u；
而项目 sm9.py 的 Fp2 表示为 (a, b) = a + b*u。换算: 本文件 (X1,X0) <-> sm9 (X0, X1)。
"""

Q = int('B640000002A3A6F1D603AB4FF58EC74521F2934B1A7AEEDBE56F9B27E351457D', 16)
N = int('B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25', 16)
T_PARAM = int('600000000058F98A', 16)


# ==================================================================
# Fp (prime field) —— 仅实现本配对所需的最小子集
# ==================================================================
def fp_add(a, b):
    return (a + b) % Q


def fp_sub(a, b):
    return (a - b) % Q


def fp_mul(a, b):
    return (a * b) % Q


def fp_neg(a):
    return (-a) % Q


def fp_inv(a):
    return pow(a % Q, Q - 2, Q)


def fp_pow(a, e):
    return pow(a % Q, e % (Q - 1), Q)


# ==================================================================
# Fp2  (X1, X0) = X0 + X1 * u ,  u^2 = -2
# ==================================================================
Z2_ZERO = (0, 0)
Z2_ONE = (0, 1)


def f2_add(x, y):
    return (fp_add(x[0], y[0]), fp_add(x[1], y[1]))


def f2_sub(x, y):
    return (fp_sub(x[0], y[0]), fp_sub(x[1], y[1]))


def f2_neg(x):
    return (fp_neg(x[0]), fp_neg(x[1]))


def f2_mul(x, y):
    a, b = x   # a = X1, b = X0  -> value = b + a*u
    c, d = y
    X1X1 = fp_mul(a, c)
    X0X0 = fp_mul(b, d)
    t = fp_mul(fp_add(a, b), fp_add(c, d))
    z1 = fp_sub(t, fp_add(X1X1, X0X0))   # = a*d + b*c  (u coeff)
    z0 = fp_add(fp_mul(-2, X1X1), X0X0)  # = -2*a*c + b*d (const)
    return (z1, z0)


def f2_inv(x):
    a, b = x
    U = -2
    # gmalg: det = U*a^2 - b^2 = -2a^2 - b^2 = -(a^2*2 + b^2) = -Norm
    # 之后 y1 = a/invdet, y0 = -b/invdet  =>  (X1, X0) = (-a/Norm, b/Norm)
    det = fp_sub(fp_mul(U, fp_mul(a, a)), fp_mul(b, b))
    invdet = fp_inv(det)
    y1 = fp_mul(a, invdet)
    y0 = fp_mul(fp_neg(b), invdet)
    return (y1, y0)


def f2_conj(x):
    a, b = x
    return (fp_neg(a), b)


def f2_pow(x, e):
    y = x
    for bit in bin(e)[3:]:
        y = f2_mul(y, y)
        if bit == '1':
            y = f2_mul(y, x)
    return y


# ==================================================================
# Fp4  (X1, X0) = X0 + X1 * v ,  v^2 = 1   (gmalg 塔式)
# 这里的乘法使用 Karatsuba，U = (0,1) 即 Fp2 中的 1
# ==================================================================
Z4_ZERO = (Z2_ZERO, Z2_ZERO)
Z4_ONE = (Z2_ZERO, Z2_ONE)


def f4_add(x, y):
    return (f2_add(x[0], y[0]), f2_add(x[1], y[1]))


def f4_sub(x, y):
    return (f2_sub(x[0], y[0]), f2_sub(x[1], y[1]))


def f4_neg(x):
    return (f2_neg(x[0]), f2_neg(x[1]))


def f4_mul(x, y):
    a, b = x
    c, d = y
    U = (1, 0)  # u  (α for Fp4 = Fp2[v]/(v^2 - u), 所以 v^2 = u)
    X1mY1 = f2_mul(a, c)
    X0mY0 = f2_mul(b, d)
    X1aX0_m_Y1aY0 = f2_mul(f2_add(a, b), f2_add(c, d))
    z1 = f2_sub(X1aX0_m_Y1aY0, f2_add(X1mY1, X0mY0))
    z0 = f2_add(f2_mul(U, X1mY1), X0mY0)
    return (z1, z0)


def f4_inv(x):
    a, b = x
    U = (1, 0)  # u (α for Fp4 = Fp2[v]/(v^2 - u), 所以 v^2 = u)
    # gmalg: det = U*a^2 - b^2 = u*X1^2 - X0^2 = -(Norm)
    det = f2_sub(f2_mul(U, f2_mul(a, a)), f2_mul(b, b))
    invdet = f2_inv(det)
    y1 = f2_mul(a, invdet)
    y0 = f2_mul(f2_neg(b), invdet)
    return (y1, y0)


def f4_conj(x):
    a, b = x
    return (f2_neg(a), b)


def f4_pmul(x, y):
    """点积式乘法：Fp4 = Fp2 分量逐点相乘，用于 Frobenius factor 运算。
    不同于 f4_mul（真正的 Fp4 域乘法）。"""
    return (f2_pmul(x[0], y[0]), f2_pmul(x[1], y[1]))


def f2_pmul(x, y):
    """Fp2 分量逐点相乘。"""
    return (fp_mul(x[0], y[0]), fp_mul(x[1], y[1]))


def f4_mul_scalar(x, n):
    return (f2_mul_scalar(x[0], n), f2_mul_scalar(x[1], n))


def f4_pow(x, e):
    y = x
    for bit in bin(e)[3:]:
        y = f4_mul(y, y)
        if bit == '1':
            y = f4_mul(y, x)
    return y


# Fp2 标量乘（Fp4/Fp12 内部会用到 f2_mul_scalar, f2_sadd 等，这里补最小实现）
def f2_mul_scalar(x, n):
    return (fp_mul(x[0], n), fp_mul(x[1], n))


def f2_sadd(x, n):
    return (x[0], fp_add(x[1], n))


def f4_sadd(x, n):
    return (x[0], f2_sadd(x[1], n))


# ==================================================================
# Fp12  (X2, X1, X0) = X0 + X1*w + X2*w^2 ,  w^3 = v = (0,1) in Fp4
# 注: gmalg 的 _ALPHA = ((0,1),(0,0)) 即 Fp4 的 (0,1) = v
# ==================================================================
Z12_ZERO = (Z4_ZERO, Z4_ZERO, Z4_ZERO)
Z12_ONE = (Z4_ZERO, Z4_ZERO, Z4_ONE)


def f12_add(x, y):
    return (f4_add(x[0], y[0]), f4_add(x[1], y[1]), f4_add(x[2], y[2]))


def f12_sub(x, y):
    return (f4_sub(x[0], y[0]), f4_sub(x[1], y[1]), f4_sub(x[2], y[2]))


def f12_neg(x):
    return (f4_neg(x[0]), f4_neg(x[1]), f4_neg(x[2]))


def f12_mul(x, y):
    """Fp12 = Fp4[w]/(w^3 - v), 其中 v 是 Fp4 元素 (u-coeff=1, const=0) 表示 v。"""
    X2, X1, X0 = x
    Y2, Y1, Y0 = y
    v = (Z2_ONE, Z2_ZERO)  # v in Fp4 = ((X1=1), (X0=0))
    C2 = f4_add(f4_add(f4_mul(X2, Y0), f4_mul(X1, Y1)), f4_mul(X0, Y2))
    C1 = f4_add(f4_add(f4_mul(X1, Y0), f4_mul(X0, Y1)), f4_mul(v, f4_mul(X2, Y2)))
    C0 = f4_add(f4_mul(X0, Y0), f4_mul(v, f4_add(f4_mul(X2, Y1), f4_mul(X1, Y2))))
    return (C2, C1, C0)


def f12_inv(x):
    X2, X1, X0 = x
    U = (Z2_ONE, Z2_ZERO)  # v in Fp4
    UmX2 = f4_mul(U, X2)
    UmX1 = f4_mul(U, X1)
    X1mX1_s_X2mX0 = f4_sub(f4_mul(X1, X1), f4_mul(X2, X0))
    UmX2mX2_s_X1X0 = f4_sub(f4_mul(UmX2, X2), f4_mul(X1, X0))
    X0mX0_s_UmX2mX1 = f4_sub(f4_mul(X0, X0), f4_mul(UmX2, X1))
    det = f4_add(f4_mul(UmX2, UmX2mX2_s_X1X0),
                  f4_add(f4_mul(UmX1, X1mX1_s_X2mX0), f4_mul(X0, X0mX0_s_UmX2mX1)))
    invdet = f4_inv(det)
    Y2 = f4_mul(X1mX1_s_X2mX0, invdet)
    Y1 = f4_mul(UmX2mX2_s_X1X0, invdet)
    Y0 = f4_mul(X0mX0_s_UmX2mX1, invdet)
    return (Y2, Y1, Y0)


def f12_pow(x, e):
    if e == 0:
        return Z12_ONE
    y = x
    for bit in bin(e)[3:]:
        y = f12_mul(y, y)
        if bit == '1':
            y = f12_mul(y, x)
    return y


def f12_smul(x, k):
    return (f4_mul_scalar(x[0], k), f4_mul_scalar(x[1], k), f4_mul_scalar(x[2], k))


def f12_sadd(x, n):
    return (x[0], f4_sadd(x[1], n))


def f12_pmul(x, y):
    """点积式乘法（逐层分量）：用于 Frobenius factor 相乘，
    不同于 f12_mul（真正的 Fp12 域乘法）。"""
    return (f4_pmul(x[0], y[0]), f4_pmul(x[1], y[1]), f4_pmul(x[2], y[2]))


# ==================================================================
# Frobenius 因子（gmalg 为这套塔式预计算的常量）
# ==================================================================
_w5 = int('2D40A38CF6983351711E5F99520347CC57D778A9F8FF4C8A4C949C7FA2A96686', 16)
_w4 = int('F300000002A3A6F2780272354F8B78F4D5FC11967BE65333', 16)
_w3 = int('6C648DE5DC0A3F2CF55ACC93EE0BAF159F9D411806DC5177F5B21FD3DA24D011', 16)
_w2 = int('F300000002A3A6F2780272354F8B78F4D5FC11967BE65334', 16)
_w1 = int('3F23EA58E5720BDB843C6CFA9C08674947C5C86E0DDD04EDA91D8354377B698B', 16)
_w0 = 1

_p = Q
FROB1_FACTOR = (((_p - _w5, _w5), (_p - _w2, _w2)), ((_p - _w4, _w4), (_p - _w1, _w1)), ((_p - _w3, _w3), (_p - _w0, _w0)))
FROB2_FACTOR = (((_p - _w4, _p - _w4), (_w4, _w4)), ((_p - _w2, _p - _w2), (_w2, _w2)), ((_p - _w0, _p - _w0), (_w0, _w0)))
FROB3_FACTOR = (((_p - _w3, _w3), (_w0, _p - _w0)), ((_p - _w0, _w0), (_p - _w3, _w3)), ((_w3, _p - _w3), (_p - _w0, _w0)))


def f12_frob1(x):
    return f12_pmul(x, FROB1_FACTOR)


def f12_frob2(x):
    return f12_pmul(x, FROB2_FACTOR)


def f12_frob3(x):
    return f12_pmul(x, FROB3_FACTOR)


def f12_frob6(x):
    X2, X1, X0 = x
    return (f4_conj(X2), f4_neg(f4_conj(X1)), f4_conj(X0))


# ==================================================================
# 曲线（gmalg 约定）: E(Fp): y^2 = x^3 + 5 ; E'(Fp2): y^2 = x^3 + 5
# 点: G1 = (x, y) in Fp ; G2 = (x, y) in Fp2 (gmalg 约定 (X1,X0))
# ==================================================================
EC1_A = 0
EC1_B = 5
EC2_A = (0, 0)
EC2_B = (0, 1)  # (0,1) in gmalg Fp2 = 1  -> b' = 5? 见 _phi；这里沿用 gmalg 常量


def ec_add_fp(x1, y1, x2, y2):
    if x1 is None:
        return (x2, y2)
    if x2 is None:
        return (x1, y1)
    if x1 == x2:
        if fp_add(y1, y2) % Q == 0:
            return (None, None)
        lam = fp_mul(fp_add(3 * fp_mul(x1, x1), EC1_A), fp_inv(2 * y1))
    else:
        lam = fp_mul(fp_sub(y2, y1), fp_inv(fp_sub(x2, x1)))
    x3 = fp_sub(fp_mul(lam, lam), fp_add(x1, x2))
    y3 = fp_sub(fp_mul(lam, fp_sub(x1, x3)), y1)
    return (x3, y3)


def ec_neg_fp(p):
    if p[0] is None:
        return p
    return (p[0], fp_neg(p[1]))


def ec_mul_fp(k, p):
    k = k % N
    if k == 0 or p[0] is None:
        return (None, None)
    result = (None, None)
    addend = p
    while k:
        if k & 1:
            result = ec_add_fp(result[0], result[1], addend[0], addend[1])
        addend = ec_add_fp(addend[0], addend[1], addend[0], addend[1])
        k >>= 1
    return result


def ec_add_fp2(x1, y1, x2, y2):
    if x1 is None:
        return (x2, y2)
    if x2 is None:
        return (x1, y1)
    if x1 == x2:
        if f2_add(y1, y2) == Z2_ZERO:
            return (None, None)
        lam = f2_mul(f2_add(f2_mul_scalar(f2_mul(x1, x1), 3), EC2_A),
                     f2_inv(f2_mul_scalar(y1, 2)))
    else:
        lam = f2_mul(f2_sub(y2, y1), f2_inv(f2_sub(x2, x1)))
    x3 = f2_sub(f2_sub(f2_mul(lam, lam), x1), x2)
    y3 = f2_sub(f2_mul(lam, f2_sub(x1, x3)), y1)
    return (x3, y3)


def ec_neg_fp2(p):
    if p[0] is None:
        return p
    return (p[0], f2_neg(p[1]))


def ec_mul_fp2(k, p):
    k = k % N
    if k == 0 or p[0] is None:
        return (None, None)
    result = (None, None)
    addend = p
    while k:
        if k & 1:
            result = ec_add_fp2(result[0], result[1], addend[0], addend[1])
        addend = ec_add_fp2(addend[0], addend[1], addend[0], addend[1])
        k >>= 1
    return result


# ==================================================================
# SM9 配对上下文
# ==================================================================
# gmalg 的 _phi / _phi_inv 与 Frobenius 上下文常量
_NEG2 = fp_sub(0, 2)                       # p - 2
_INV_NEG2 = fp_inv(_NEG2)


def _phi(P):
    """(x_, y_) in E'(Fp2, gmalg 约定) -> E(Fp12)。
    x_ = (X1, X0) 表示 X0 + X1*u (gmalg: X1=u-coeff, X0=const)。
    构造 Fp12 = (X2, X1, X0)，其中 X1 的 Fp4 的 high Fp2 = (X0*(-1/2), X1)。
    """
    x_, y_ = P
    # X1 的 Fp4 的 high Fp2 = (u-coeff, const) = (X0*(-1/2), X1)
    x_high_fp2 = (fp_mul(x_[1], _INV_NEG2), x_[0])
    x_mid_fp4 = (x_high_fp2, Z2_ZERO)  # Fp4 = (high Fp2, low Fp2)
    x = (Z4_ZERO, x_mid_fp4, Z4_ZERO)  # Fp12 = (X2, X1, X0)

    y_high_fp2 = (fp_mul(y_[1], _INV_NEG2), y_[0])
    y_x0_fp4 = (y_high_fp2, Z2_ZERO)
    y = (Z4_ZERO, Z4_ZERO, y_x0_fp4)
    return (x, y)


def _phi_inv(P):
    x_, y_ = P
    # X1 的 Fp4 的 high Fp2 = x_[1][0] = (u-coeff, const)
    # 反解: 原 Fp2 = (X1=u-coeff, X0=const) = (const_of_x_highFp2, u-coeff_of_x_highFp2 * (-2))
    x = (x_[1][0][1], fp_mul(x_[1][0][0], _NEG2))
    y = (y_[2][0][1], fp_mul(y_[2][0][0], _NEG2))
    return (x, y)


def _g_fn(U, V, Qp):
    """line function g_{U,V}(Qp), all Fp12 points."""
    if U[0] is None or V[0] is None or Qp[0] is None:
        return Z12_ONE
    xU, yU = U
    xV, yV = V
    xQ, yQ = Qp
    if xU == xV:
        if yU == yV:
            # 加倍：切线 λ = 3x² / 2y
            lam = f12_mul(f12_smul(f12_mul(xV, xV), 3),
                          f12_inv(f12_smul(yV, 2)))
        else:
            # 竖直线（V = -U）：线方程为 x = xV，贡献 (xQ - xV)
            return f12_sub(xQ, xV)
    else:
        lam = f12_mul(f12_sub(yU, yV), f12_inv(f12_sub(xU, xV)))
    g = f12_sub(f12_mul(lam, f12_sub(xQ, xV)), f12_sub(yQ, yV))
    return g


def f12_one():
    return Z12_ONE


def _extend_fp(x):
    """把 Fp 整数 x 扩展为 Fp12 常量项（C0 的 Fp4 的 Fp2 的常量分量）。"""
    return (Z4_ZERO, Z4_ZERO, (Z2_ZERO, (0, x % Q)))


def _finalexp(f):
    M = f12_mul
    I = f12_inv
    P = f12_pow
    F1 = f12_frob1
    F2 = f12_frob2
    F3 = f12_frob3
    F6 = f12_frob6
    # easy part
    f = M(F6(f), I(f))
    f = M(F2(f), f)
    # hard part
    f_t = P(f, T_PARAM)
    f_t2 = P(f_t, T_PARAM)
    f_t3 = P(f_t2, T_PARAM)
    f_p = F1(f)
    f_p2 = F2(f)
    f_p3 = F3(f)
    f_t_p = F1(f_t)
    f_t2_p = F1(f_t2)
    f_t3_p = F1(f_t3)
    f_t2_p2 = F2(f_t2)
    y6 = P(M(f_t3, f_t3_p), 36)
    y5 = P(f_t2, 30)
    y4 = P(M(f_t2_p, f_t), 18)
    y3 = P(f_t_p, 12)
    y2 = P(f_t2_p2, 6)
    y1 = M(f, f)
    y0 = M(f_p, M(f_p2, f_p3))
    f_num = M(y2, y0)
    f_den = M(y6, M(y5, M(y4, M(y3, y1))))
    f = M(f_num, I(f_den))
    return f


def _fp_to_b(a):
    """Fp 元素 -> 32 字节大端。"""
    return (a % Q).to_bytes(32, 'big')


def fp2_to_b(el):
    """gmalg Fp2 (X1, X0) -> 64 字节。顺序: X1 32B || X0 32B。"""
    X1, X0 = el
    return _fp_to_b(X1) + _fp_to_b(X0)


def fp4_to_b(el):
    """gmalg Fp4 (X1, X0) -> 128 字节。顺序: X1 64B || X0 64B。"""
    X1, X0 = el
    return fp2_to_b(X1) + fp2_to_b(X0)


def fp12_to_b(el):
    """gmalg Fp12 (C2, C1, C0) -> 384 字节。顺序: C2 || C1 || C0 (各 128B)。
    与 gmalg PrimeField12.etob 保持一致。"""
    C2, C1, C0 = el
    return fp4_to_b(C2) + fp4_to_b(C1) + fp4_to_b(C0)


def gt_to_bytes(f12_el):
    """GT = Fp12 元素 -> 384 字节。用于 H2 哈希输入。"""
    return fp12_to_b(f12_el)


def point_g1_to_bytes(p):
    """G1 点 (x, y) -> 65 字节非压缩 (0x04 || x || y)。"""
    x, y = p
    return b'\x04' + _fp_to_b(x) + _fp_to_b(y)


def pair(P, Q):
    """R-ate 配对 e(P, Q), P in G1 (Fp), Q in G2 (Fp2 gmalg 约定)。"""
    _P = _extend_fp(P[0]), _extend_fp(P[1])
    _Q = _phi(Q)
    T = Q
    f = f12_one()
    for i in "00100000000000000000000000000000000000010000101011101100100111110":
        _T = _phi(T)
        g = _g_fn(_T, _T, _P)
        f = f12_mul(f12_mul(f, f), g)
        T = ec_add_fp2(T[0], T[1], T[0], T[1])
        if i == '1':
            g = _g_fn(_phi(T), _Q, _P)
            f = f12_mul(f, g)
            T = ec_add_fp2(T[0], T[1], Q[0], Q[1])
    Q1 = (f12_frob1(_Q[0]), f12_frob1(_Q[1]))
    Q2 = (f12_frob2(_Q[0]), f12_neg(f12_frob2(_Q[1])))
    g = _g_fn(_phi(T), Q1, _P)
    f = f12_mul(f, g)
    T = ec_add_fp2(T[0], T[1], _phi_inv(Q1)[0], _phi_inv(Q1)[1])
    g = _g_fn(_phi(T), Q2, _P)
    f = f12_mul(f, g)
    return _finalexp(f)
