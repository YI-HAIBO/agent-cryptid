# -*- coding: utf-8 -*-
"""纯 Python 实现 Keccak-f[1600] 与 SHA3 / SHAKE 系列（零依赖）。

用于 agent-cryptid 抗量子档位的底层哈希原语：
    - SHA3-256 / SHA3-512（FIPS 202）
    - SHAKE128 / SHAKE256（FIPS 202 可扩展输出函数）

实现要点：
    - 标准 "planar" lane 布局：state[i] = lane at (x = i % 5, y = i // 5)
    - 多速率填充（pad10*1）：SHA3 域字节 0x06，SHAKE 域字节 0x1f
    - 已用 NIST 已知向量自测（见 self_check）

注：本模块为教学/原型用途，性能非首要目标；正确性优先。
"""
MASK64 = (1 << 64) - 1

# Rho 旋转偏移 R[x][y]（FIPS 202 表）
_RHO = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
]

# Iota 轮常数（24 轮）
_RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
    0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
    0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
    0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
    0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
]


def _rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & MASK64


def _keccak_f1600(state):
    """原地执行 Keccak-f[1600]（24 轮）。state: 25 个 64 位 lane 的列表。"""
    for rnd in range(24):
        # Theta
        C = [state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20]
             for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] ^= D[x]
        # Rho + Pi
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(state[x + 5 * y], _RHO[x][y])
        # Chi
        for x in range(5):
            for y in range(5):
                state[x + 5 * y] = B[x + 5 * y] ^ (
                    (~B[((x + 1) % 5) + 5 * y]) & B[((x + 2) % 5) + 5 * y])
        # Iota
        state[0] ^= _RC[rnd]
    return state


def _sponge(rate, delim, msg, out_len):
    """通用 Keccak 海绵：吸收 msg（含域分隔符）+ 多速率填充，挤压出 out_len 字节。"""
    state = [0] * 25
    m = bytearray(msg)
    m.append(delim)
    while len(m) % rate != 0:
        m.append(0x00)
    m[-1] ^= 0x80
    # 吸收
    for off in range(0, len(m), rate):
        block = m[off:off + rate]
        nqw = len(block) // 8
        for i in range(nqw):
            state[i] ^= int.from_bytes(block[i * 8:i * 8 + 8], "little")
        _keccak_f1600(state)
    # 挤压
    out = bytearray()
    while len(out) < out_len:
        for i in range(rate // 8):
            out += state[i].to_bytes(8, "little")
        if len(out) < out_len:
            _keccak_f1600(state)
    return bytes(out[:out_len])


# ---- 标准接口 ----
def sha3_224(msg):
    return _sponge(144, 0x06, msg, 28)


def sha3_256(msg):
    return _sponge(136, 0x06, msg, 32)


def sha3_384(msg):
    return _sponge(104, 0x06, msg, 48)


def sha3_512(msg):
    return _sponge(72, 0x06, msg, 64)


def shake128(msg, out_len):
    return _sponge(168, 0x1F, msg, out_len)


def shake256(msg, out_len):
    return _sponge(136, 0x1F, msg, out_len)


def self_check():
    """NIST 已知向量自测。"""
    out = []
    # SHA3-256("")
    out.append(("SHA3-256 empty",
                sha3_256(b"") ==
                bytes.fromhex("a7ffc6f8bf1ed76651c14756a061d662"
                              "f580ff4de43b49fa82d80a4b80f8434a")))
    # SHA3-512("")
    out.append(("SHA3-512 empty",
                sha3_512(b"") ==
                bytes.fromhex("a69f73cca23a9ac5c8b567dc185a756"
                              "e97c982164fe25859e0d1dcc1475c80a6"
                              "15b2123af1f5f94c11e3e9402c3ac558"
                              "f500199d95b6d3e301758586281dcd26")))
    # SHA3-256("abc")
    out.append(("SHA3-256 abc",
                sha3_256(b"abc") ==
                bytes.fromhex("3a985da74fe225b2045c172d6bd390bd"
                              "855f086e3e9d525b46bfe24511431532")))
    # SHAKE128("", 32)
    out.append(("SHAKE128 empty 32",
                shake128(b"", 32) ==
                bytes.fromhex("7f9c2ba4e88f827d616045507605853e"
                              "d73b8093f6efbc88eb1a6eacfa66ef26")))
    # SHAKE256("", 64)
    out.append(("SHAKE256 empty 64",
                shake256(b"", 64) ==
                bytes.fromhex("46b9dd2b0ba88d13233b3feb743eeb24"
                              "3fcd52ea62b81b82b50c27646ed5762f"
                              "d75dc4ddd8c0f200cb05019d67b592f6"
                              "fc821c49479ab48640292eacb3b7c4be")))
    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-16s %s" % ("PASS" if ok else "FAIL", name))
