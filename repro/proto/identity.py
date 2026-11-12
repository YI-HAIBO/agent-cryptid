# -*- coding: utf-8 -*-
"""身份层：智能体标识密钥的签发与验签。

v0.1 原型定位：用 SM2 作为签名底层，主密钥 mk 侧通过 SM3-KDF 确定性派生
标识密钥对 (d_id, pub_id)。标识既进入 KDF 输入（决定 d_id），也进入
GB/T 32918.4 的 ZA（决定签名摘要），双重绑定标识。

v2.6 起支持真 SM9（GM/T 0044）作为可选签名算法：主签名私钥 ks 直接
参与用户私钥派生（ds_A = [t2] P1），P_pub = [ks] P2 是主签名公钥。
SM9 的"无证书"特性意味着验签方只需知道 P_pub 和 ID 即可，无需下发
用户公钥——这正是智能体场景（分钟级生灭、海量命名空间）需要的能力。

接口：
    IdentityAuthority()               -> 信任根（含 SM2 与 SM9 两套密钥）
    ia.issue(idn)                     -> (d_id, pub_id)  CA 侧 SM2 派生
    ia.issue_sm9(idn)                 -> ds_A              CA 侧 SM9 派生
    ia.get_pub(idn)                   -> pub_id            CA 登记簿查询
    ia.sign(idn, msg)                 -> (r, s)            CA 持 d_id 时
    ia.sign_sm9(idn, msg)             -> (h, S)            CA 持 ks 时
    verify_id(idn, pub_id, r, s, m)   -> bool
    verify_id_sm9(idn, h, S, m)       -> bool
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sm2  # noqa: E402

# 快路径：gmssl 加速签名
try:
    from sm2_fast import FastSigner as _FastSigner
    _FAST_AVAILABLE = True
except ImportError:
    _FastSigner = None
    _FAST_AVAILABLE = False

# SM9 真实现（v2.6 加入）
try:
    import sm9 as _SM9
    _SM9_AVAILABLE = True
except ImportError:
    _SM9 = None
    _SM9_AVAILABLE = False


KDF_DOMAIN = b"agent-cryptid::identity-derive::v1"


def _kdf(master_key, idn):
    """SM3-HMAC 派生 256 位标识密钥种子。"""
    # 简易 HMAC-SM3：单轮即可（原型用途）
    inner = sm2.sm3(bytes(b ^ 0x36 for b in _key_pad(master_key)) + idn)
    return sm2.sm3(bytes(b ^ 0x5C for b in _key_pad(master_key)) + inner)


def _key_pad(mk_bytes):
    """把 mk 转为 32 字节键材料。"""
    if isinstance(mk_bytes, int):
        mk_bytes = mk_bytes.to_bytes(32, "big")
    if len(mk_bytes) > 32:
        mk_bytes = sm2.sm3(mk_bytes)
    return mk_bytes + b"\x00" * (32 - len(mk_bytes))


class IdentityAuthority:
    """信任根：主密钥 + 标识登记簿。

    v2.6 起同时持 SM2 与 SM9 两套密钥：
    - SM2: mk（标量私钥），派生 d_id / pub_id
    - SM9: ks（主签名私钥），派生 ds_A，主公钥 P_pub = [ks] * P2

    v2.13 FR1-05：主密钥轮换支持——_mk_history 存储 (version, mk, mpk)
    列表，version=0 为首版，每次 rotate 追加新版。标识记录 key_version
    字段指示该标识用哪个版本的 mk 派生。轮换不影响既有标识：
    旧标识仍用旧 mk 派生私钥（签名不变），新标识用新 mk。
    """

    def __init__(self):
        self._mk_history = []  # [(version, mk, mpk), ...]
        self.mk = secrets.randbelow(sm2.N - 1) + 1
        self.mpk = sm2.scalar_mult(self.mk)
        self._mk_history.append((0, self.mk, self.mpk))
        self._registry = {}  # idn -> {"pub": pub_id, "key_version": v}
        # SM9 密钥（v2.6 新增，v2.13 支持轮换）
        self._ks_history = []  # [(version, ks, ppub), ...]
        if _SM9_AVAILABLE:
            self.ks = secrets.randbelow(_SM9.N - 1) + 1
            self.ppub = _SM9.g2_mul(self.ks, _SM9.P2)
            self._ks_history.append((0, self.ks, self.ppub))
        else:
            self.ks = None
            self.ppub = None

    @property
    def current_mk_version(self):
        return self._mk_history[-1][0]

    @property
    def current_ks_version(self):
        return self._ks_history[-1][0]

    def _get_mk(self, version=None):
        """按版本取 mk；None 取当前（最新）版。"""
        if version is None:
            return self.mk
        for v, mk, _ in self._mk_history:
            if v == version:
                return mk
        raise ValueError("unknown key version: %s" % version)

    def _get_ks(self, version=None):
        """按版本取 ks；None 取当前（最新）版。"""
        if version is None:
            return self.ks
        for v, ks, _ in self._ks_history:
            if v == version:
                return ks
        raise ValueError("unknown ks version: %s" % version)

    def rotate_mk(self):
        """FR1-05：轮换 SM2 主密钥。返回 (new_version, new_mk, new_mpk)。"""
        new_mk = secrets.randbelow(sm2.N - 1) + 1
        new_mpk = sm2.scalar_mult(new_mk)
        new_ver = self.current_mk_version + 1
        self._mk_history.append((new_ver, new_mk, new_mpk))
        self.mk = new_mk
        self.mpk = new_mpk
        return new_ver, new_mk, new_mpk

    def rotate_ks(self):
        """FR1-05：轮换 SM9 主签名私钥。返回 (new_version, new_ks, new_ppub)。"""
        if not _SM9_AVAILABLE:
            raise RuntimeError("SM9 未编译")
        new_ks = secrets.randbelow(_SM9.N - 1) + 1
        new_ppub = _SM9.g2_mul(new_ks, _SM9.P2)
        new_ver = self.current_ks_version + 1
        self._ks_history.append((new_ver, new_ks, new_ppub))
        self.ks = new_ks
        self.ppub = new_ppub
        return new_ver, new_ks, new_ppub

    def key_versions(self):
        """返回已轮换的主密钥版本信息（不含 mk 明文）。"""
        return {
            "sm2": {
                "current_version": self.current_mk_version,
                "versions": [{"version": v, "rotated": v > 0}
                              for v, _, _ in self._mk_history],
            },
            "sm9": {
                "current_version": self.current_ks_version,
                "versions": [{"version": v, "rotated": v > 0}
                              for v, _, _ in self._ks_history],
            },
        }

    def issue(self, idn, key_version=None):
        """为标识 idn 派生密钥对（SM2），登记 pub_id，返回 (d_id, pub_id, version)。

        key_version=None 时用当前最新 mk；指定时用对应版本（供轮换后重建）。
        """
        mk = self._get_mk(key_version)
        d_id = int.from_bytes(_kdf(mk, idn), "big") % (sm2.N - 1) + 1
        if idn in self._registry:
            rec = self._registry[idn]
            # 幂等：同一标识二次签发返回同一密钥（版本号不变）
            return d_id, rec["pub"], rec["key_version"]
        pub_id = sm2.scalar_mult(d_id)
        ver = key_version if key_version is not None else self.current_mk_version
        self._registry[idn] = {"pub": pub_id, "key_version": ver}
        return d_id, pub_id, ver

    def get_pub(self, idn):
        rec = self._registry.get(idn)
        return rec["pub"] if rec else None

    def get_key_version(self, idn):
        rec = self._registry.get(idn)
        return rec["key_version"] if rec else None

    def sign(self, idn, msg, key_version=None):
        """用标识密钥签名（要求身份已被签发）。key_version 指定用哪个 mk。"""
        rec = self._registry.get(idn)
        if rec is None:
            raise ValueError("identity not issued: %s" % idn)
        mk = self._get_mk(key_version if key_version is not None else rec["key_version"])
        d_id = int.from_bytes(_kdf(mk, idn), "big") % (sm2.N - 1) + 1
        if not _FAST_AVAILABLE:
            return sm2.sign(idn, d_id, msg)
        pub_id = rec["pub"]
        fs = _FastSigner(d_id, pub_id)
        return fs.sign(idn, msg)

    # ---- v2.6 新增：SM9 无证书签名 ----
    def issue_sm9(self, idn, key_version=None):
        """为标识 idn 派生 SM9 用户私钥 ds_A（G1 点）。
        SM9 无需登记公钥——验签方只需 P_pub 与 ID。
        key_version 指定用哪个版本的 ks（None=当前最新）。"""
        if not _SM9_AVAILABLE or self.ks is None:
            raise RuntimeError("SM9 未编译")
        ks = self._get_ks(key_version)
        idn_bytes = idn.encode("utf-8") if isinstance(idn, str) else idn
        ds_A, _t1, _t2, _h1 = _SM9.derive_user_key(idn_bytes, ks)
        return ds_A

    def sign_sm9(self, idn, msg, key_version=None):
        """用 SM9 主签名私钥 ks 对消息签名。返回 (h, S)。
        key_version 指定用哪个版本的 ks（None=当前最新）。"""
        if not _SM9_AVAILABLE or self.ks is None:
            raise RuntimeError("SM9 未编译")
        ks = self._get_ks(key_version)
        idn_bytes = idn.encode("utf-8") if isinstance(idn, str) else idn
        ds_A, _, _, _ = _SM9.derive_user_key(idn_bytes, ks)
        # P_pub 用对应版本的（验签方需匹配）
        ppub = self._get_ppub(key_version)
        return _SM9.sign(msg if isinstance(msg, bytes) else msg.encode("utf-8"),
                         ds_A, P_pub_g2=ppub)

    def _get_ppub(self, version=None):
        """按版本取 P_pub。"""
        if version is None:
            return self.ppub
        for v, _, p in self._ks_history:
            if v == version:
                return p
        raise ValueError("unknown ks version: %s" % version)

    def get_ppub(self):
        """返回 SM9 主签名公钥 P_pub（G2 点）。"""
        return self.ppub


def verify_id(idn, pub_id, r, s, msg):
    """无证书侧验签：只需知道 idn 与 pub_id。"""
    if _FAST_AVAILABLE:
        fs = _FastSigner(1, pub_id)  # priv=1 占位，verify 不用
        return fs.verify(idn, r, s, msg)
    return sm2.verify(idn, pub_id, r, s, msg)


def verify_id_sm9(idn, h, S, msg, ppub):
    """SM9 无证书侧验签：只需知道 ID、P_pub 与签名 (h, S)。"""
    if not _SM9_AVAILABLE:
        raise RuntimeError("SM9 未编译")
    idn_bytes = idn.encode("utf-8") if isinstance(idn, str) else idn
    msg_bytes = msg if isinstance(msg, bytes) else msg.encode("utf-8")
    return _SM9.verify(msg_bytes, h, S, idn_bytes, ppub)


def self_check():
    """内部自检。"""
    out = []
    ia = IdentityAuthority()

    # 同一标识多次签发返回同一密钥对
    d1, p1, v1 = ia.issue(b"agent://a/1")
    d2, p2, v2 = ia.issue(b"agent://a/1")
    out.append(("同一标识签发幂等", (d1, p1, v1) == (d2, p2, v2)))

    # 不同标识派生不同公钥
    _, p_a, _ = ia.issue(b"agent://a")
    _, p_b, _ = ia.issue(b"agent://b")
    out.append(("不同标识公钥不同", p_a != p_b))

    # 签发 → 验签往返
    idn = b"agent://demo-org/ops-agent-001"
    msg = b"issue credential for tool call invoice:read"
    d_id, pub_id, _ = ia.issue(idn)
    r, s = ia.sign(idn, msg)
    out.append(("标识签名往返验签通过", verify_id(idn, pub_id, r, s, msg)))

    # 篡改标识 → 失败（ZA 绑定）
    out.append(("更换标识后验签失败",
                not verify_id(b"agent://other/x", pub_id, r, s, msg)))

    # 篡改消息 → 失败
    out.append(("篡改消息后验签失败",
                not verify_id(idn, pub_id, r, s, msg + b"x")))

    return out


if __name__ == "__main__":
    for name, ok in self_check():
        print("%-8s %s" % ("PASS" if ok else "FAIL", name))
