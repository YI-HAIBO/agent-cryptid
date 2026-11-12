# -*- coding: utf-8 -*-
"""纯 Python 实现 SLH-DSA（SPHINCS+ 核心：WOTS+ 一次性签名 + MERKLE 超树）— 零依赖。

参数集（缩减，纯 Python 原型用；生产请用完整 FIPS 205 参数集）：
    n       = 4     安全参数（哈希输出字节数，32 位）
    w       = 16    WOTS+ 基数（链长 M = w-1 = 15）
    μ       = 1     安全因子
    h_total = 8     MERKLE 超树总高度（= FIPS 205 的 h + H，合并简化）
    哈希     = SHAKE256（FIPS 202），地址化域分离（ADRS 风格）

结构：
    pk  = MERKLE 超树根（n 字节）
    叶  = WOTS+ 根值（N_CHAIN 条链根拼接哈希）
    WOTS+ 含校验和链（保证 w-进制数字完整性，FIPS 205 Alg 8/9 风格）

签名容量 = 2^h_total = 256
签名大小 ≈ N_CHAIN·n + h_total·n + n + 1 = 40 + 32 + 4 + 1 = 77 字节

局限（原型）：
    h_total=8 使签名容量仅 256，生日碰撞概率随消息数增大。
    完整 SPHINCS+ 用 FORS 层提供更大容量（2^(H+h) 可达 2^127）。
    生产环境请使用 FIPS 205 完整参数集（如 SPHINCS+SHA-128s）。
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shake  # noqa: E402

# ---------------- 参数 ----------------
N_PARAM = 4            # 哈希输出字节数
W = 16                 # WOTS+ 基数
M = W - 1              # WOTS+ 链长（最大迭代次数）
WOTS_BITS = (W - 1).bit_length()   # 4
MU = 1                 # 安全因子（保留常量）
H_TOTAL = 8            # MERKLE 超树高度
SIGN_CAP = 1 << H_TOTAL            # 签名容量 256
N_CHAIN_MSG = -(-(N_PARAM * 8) // WOTS_BITS)         # 8 个消息链
N_CHAIN_CHK = -(-((N_CHAIN_MSG * M).bit_length() or 1) // WOTS_BITS)  # 2 个校验链
N_CHAIN = N_CHAIN_MSG + N_CHAIN_CHK                   # 10 条链
CHK_CAP = N_CHAIN_MSG * M                             # 校验和上界 120
WOTS_MASK = (1 << WOTS_BITS) - 1


# ---------------- 哈希 ----------------
def _h(msg):
    """n 字节哈希（SHAKE256 截断）。"""
    return shake.shake256(msg, N_PARAM)


# ---------------- WOTS+（FIPS 205 Alg 8/9 风格） ----------------
def _wots_at(seed, pos, coord):
    """从种子下溯到位置 pos：H^pos(seed)（各层用不同地址标签）。"""
    x = seed
    for lv in range(pos):
        x = _h(b"W" + bytes([coord & 0xFF]) + lv.to_bytes(4, "little") + x)
    return x


def _wots_hash_up(el, from_pos, coord):
    """从位置 from_pos 上溯到位置 M（根）：H^(M-from_pos)(el)。"""
    x = el
    for lv in range(from_pos, M):
        x = _h(b"W" + bytes([coord & 0xFF]) + lv.to_bytes(4, "little") + x)
    return x


def _wots_digits(msg):
    """n 字节消息 → N_CHAIN 个 w-进制数字（含校验和链）。"""
    digits = []
    for i in range(N_CHAIN_MSG):
        off = i * WOTS_BITS
        digits.append((msg[off >> 3] >> (off & 7)) & WOTS_MASK)
    cksum = CHK_CAP - sum(digits)
    for i in range(N_CHAIN_CHK):
        digits.append((cksum >> (i * WOTS_BITS)) & WOTS_MASK)
    return digits


def _wots_roots(seeds):
    """N_CHAIN 个种子 → 拼接哈希的 WOTS+ 根值（n 字节）。"""
    return _h(b"WR" + b"".join(_wots_at(s, M, i) for i, s in enumerate(seeds)))


# ---------------- MERKLE 超树 ----------------
def _build_merkle(leaves):
    """构建 MERKLE 超树：tree[depth][pos]，depth=0 为叶。"""
    tree = [list(leaves)]
    d = 0
    while len(tree[-1]) > 1:
        prev = tree[-1]
        new = [_h(b"M" + d.to_bytes(4, "little") + prev[i] + prev[i + 1])
               for i in range(0, len(prev), 2)]
        tree.append(new)
        d += 1
    return tree


def _merkle_path(tree, leaf_idx):
    """从叶子 leaf_idx 到根的部分路径（H_TOTAL 个兄弟节点）。"""
    path = []
    pos = leaf_idx
    for d in range(len(tree) - 1):
        path.append(tree[d][pos ^ 1])
        pos >>= 1
    return path


def _merkle_verify(leaf_val, path, leaf_idx):
    """从叶子值和路径上溯验证到根。"""
    x = leaf_val
    pos = leaf_idx
    for d, sib in enumerate(path):
        x = (_h(b"M" + d.to_bytes(4, "little") + sib + x) if pos & 1
             else _h(b"M" + d.to_bytes(4, "little") + x + sib))
        pos >>= 1
    return x


# ---------------- 密钥 / 签名 / 验签 ----------------
def keygen(seed=None):
    """生成 (pk, sk)。seed 提供可复现性（用于持久化/回归测试）。"""
    if seed is None:
        seed = os.urandom(32)
    master = shake.shake256(seed, 32)
    seeds_all = []
    leaves = []
    for li in range(SIGN_CAP):
        chain_seeds = [_h(b"S" + li.to_bytes(4, "little") + bytes([i]) + master)
                       for i in range(N_CHAIN)]
        seeds_all.append(chain_seeds)
        leaves.append(_wots_roots(chain_seeds))
    tree = _build_merkle(leaves)
    pk = tree[-1][0]
    sk = {"master": master, "seeds": seeds_all, "tree": tree}
    return pk, sk


def sign(sk, msg):
    """对 msg（bytes）签名。返回 sig dict。"""
    m_hash = _h(b"MSG" + msg)
    leaf = int.from_bytes(_h(b"L" + m_hash), "little") % SIGN_CAP
    digits = _wots_digits(m_hash)
    sig = [_wots_at(sk["seeds"][leaf][i], d, i) for i, d in enumerate(digits)]
    path = _merkle_path(sk["tree"], leaf)
    return {"m": m_hash, "leaf": leaf, "sig": sig, "path": path}


def verify(pk, msg, sig):
    """验签。返回 bool。"""
    try:
        m_hash = sig["m"]
        leaf = sig["leaf"]
        sigs = sig["sig"]
        path = sig["path"]
    except (KeyError, TypeError):
        return False
    if m_hash != _h(b"MSG" + msg):
        return False
    if not isinstance(sigs, (list, tuple)) or len(sigs) != N_CHAIN:
        return False
    digits = _wots_digits(m_hash)
    roots = [_wots_hash_up(sigs[i], digits[i], i) for i in range(N_CHAIN)]
    leaf_val = _h(b"WR" + b"".join(roots))
    return _merkle_verify(leaf_val, path, leaf) == pk


# ---------------- 序列化（JSON 友好，便于 wire/持久化） ----------------
def pk_to_json(pk):
    return {"pk": pk.hex()}


def pk_from_json(d):
    return bytes.fromhex(d["pk"])


def sk_to_json(sk):
    return {"master": sk["master"].hex(),
            "seeds": [[s.hex() for s in chains] for chains in sk["seeds"]]}


def sk_from_json(d):
    return {"master": bytes.fromhex(d["master"]),
            "seeds": [[bytes.fromhex(s) for s in chains]
                      for chains in d["seeds"]]}


def sig_to_json(sig):
    return {"m": sig["m"].hex(), "leaf": sig["leaf"],
            "sig": [s.hex() for s in sig["sig"]],
            "path": [s.hex() for s in sig["path"]]}


def sig_from_json(d):
    return {"m": bytes.fromhex(d["m"]), "leaf": d["leaf"],
            "sig": [bytes.fromhex(s) for s in d["sig"]],
            "path": [bytes.fromhex(s) for s in d["path"]]}


# ---------------- 自测 ----------------
def self_check():
    out = []
    # 参数一致性
    out.append(("参数一致", N_CHAIN_MSG + N_CHAIN_CHK == N_CHAIN))
    # 密钥生成 + 签名 + 验签闭环
    pk, sk = keygen(seed=b"\x00" * 32)
    msg = b"agent-cryptid hash-based signature"
    sig = sign(sk, msg)
    out.append(("签名-验签闭环", verify(pk, msg, sig)))
    # 确定性（同一 msg 产生同一签名）
    sig2 = sign(sk, msg)
    out.append(("签名确定性", sig_to_json(sig) == sig_to_json(sig2)))
    # 篡改消息应失败
    out.append(("篡改消息失败", not verify(pk, msg + b"x", sig)))
    # 篡改签名应失败
    bad = sig_to_json(sig)
    bad["sig"][0] = "00" * N_PARAM
    out.append(("篡改签名失败", not verify(pk, msg, sig_from_json(bad))))
    # 篡改路径应失败
    bad2 = sig_to_json(sig)
    bad2["path"][0] = "ff" * N_PARAM
    out.append(("篡改路径失败", not verify(pk, msg, sig_from_json(bad2))))
    # 序列化往返
    out.append(("序列化往返", verify(pk, msg, sig_from_json(sig_to_json(sig)))))
    # 不同消息使用不同叶子（降低 WOTS+ 复用概率）
    leaves = set()
    for i in range(8):
        s = sign(sk, ("msg-%d" % i).encode())
        leaves.add(s["leaf"])
    out.append(("多消息独立叶子", len(leaves) >= 6))
    return out


if __name__ == "__main__":
    import time as _t
    for name, ok in self_check():
        print("%-22s %s" % ("PASS" if ok else "FAIL", name))
    t0 = _t.perf_counter()
    pk, sk = keygen(seed=b"\x00" * 32)
    print("keygen elapsed       %.3fs" % (_t.perf_counter() - t0))
    t0 = _t.perf_counter()
    for i in range(5):
        m = ("perf-%d" % i).encode()
        s = sign(sk, m)
        verify(pk, m, s)
    print("5x sign+verify       %.3fs" % (_t.perf_counter() - t0))
