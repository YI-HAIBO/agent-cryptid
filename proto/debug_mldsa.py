# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mldsa
Q = mldsa.Q; N = mldsa.N; Z = mldsa.ZETA

# 验证 zeta 是否 512 次根
print("zeta^256 mod q == q-1 ?", pow(Z, 256, Q) == Q-1)
print("zeta^512 mod q == 1 ?", pow(Z, 512, Q) == 1)

a = [0,1] + [0]*(N-2)
an = mldsa.ntt(a)
print("ntt(X)[0..3] =", an[:4], "expect", [pow(Z,1,Q), pow(Z,3,Q), pow(Z,5,Q), pow(Z,7,Q)])
an2 = mldsa.poly_mul_ntt(an, an)
print("an2[0] =", an2[0], "expect zeta^2 =", pow(Z,2,Q))
# 手算 nttinv(an2)[2]
acc = 0
for i in range(N):
    acc = (acc + an2[i] * mldsa._INV[2][i]) % Q
print("sum_i r_i^2 * r_i^-2 =", acc, "expect 256")
print("NINV =", mldsa.NINV, "256*NINV mod q =", (256*mldsa.NINV)%Q)
print("nttinv(an2)[2] =", mldsa.nttinv(an2)[2])
