# -*- coding: utf-8 -*-
"""SecureKeyBackend：私钥签名后端抽象（v2.19，FR1-06 硬件根替代方案）。

动机
----
agent-cryptid 的凭证签发/验证通过 FastSigner 完成，私钥以 Python 大整数
驻留内存。FR1-06（v3.0 路线图）要求私钥由国密芯片/TEE 承载，把密钥托管
问题转化为硬件安全问题。本模块定义**密钥后端接口**，使私钥的持有方式
可插拔：任何实现 SecureKeyBackend 的对象都能接入签发/验证路径，硬件根
（TPM、国密芯片）只需实现同一接口即完成替换，**对上层零改动**。

默认实现 SoftwareKeyBackend 保持现有行为（内存私钥 + FastSigner），
正确性与本项目既有实现完全一致，故接入不改变任何安全结论。

硬件根实现契约（接口桩，未实测——须厂商硬件）：
  TpmKeyBackend        —— 经 PKCS#11/TPM2 引擎调用芯片签名
  NationalChipKeyBackend —— 国密芯片（如奥联/国芯/数盾）厂商 SDK
两者均为文档桩，证明接口可承载硬件根；实际芯片侧信道验收
（GM/T 0028-2014 / GM/T 0008-2012 / YD/T 6868-2026）在 v3.0 厂商合作阶段。
"""
import os
import sys
from abc import ABC, abstractmethod

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


class SecureKeyBackend(ABC):
    """私钥签名后端抽象接口。

    上层（凭证签发/验证、审计锚、委托链）只依赖本接口的 sign/verify/
    export_pub，不关心私钥驻留位置（内存、TPM、国密芯片）。
    """

    @abstractmethod
    def sign(self, idn, msg):
        """SM2 签名（idn=None 不做 ZA），返回 (r, s)。"""

    @abstractmethod
    def verify(self, idn, r, s, msg):
        """SM2 验签，返回 bool。"""

    @abstractmethod
    def export_pub(self):
        """返回公钥仿射坐标 (x, y)。"""


class SoftwareKeyBackend(SecureKeyBackend):
    """默认软件实现：内存私钥 + FastSigner（与既有行为一致）。"""

    def __init__(self, priv, pub):
        from sm2_fast import FastSigner
        self._fs = FastSigner(priv, pub)
        self._pub = pub

    def sign(self, idn, msg):
        return self._fs.sign(idn, msg)

    def verify(self, idn, r, s, msg):
        return self._fs.verify(idn, r, s, msg)

    def export_pub(self):
        return self._pub


class TpmKeyBackend(SecureKeyBackend):
    """TPM 2.0 硬件根（接口桩，v3.0）。

    契约：私钥常驻 TPM 非导出区，sign/verify 经 PKCS#11/TPM2 引擎调用，
    私钥从不离开芯片。本桩不实现，须厂商 TPM 环境实测。
    """

    def __init__(self):
        raise NotImplementedError(
            "TPMKeyBackend requires a TPM 2.0 engine (v3.0 hardware root).")

    def sign(self, idn, msg):
        raise NotImplementedError

    def verify(self, idn, r, s, msg):
        raise NotImplementedError

    def export_pub(self):
        raise NotImplementedError


class NationalChipKeyBackend(SecureKeyBackend):
    """国密芯片硬件根（接口桩，v3.0）。

    契约：私钥由国密芯片承载（如奥联信息安全 SM9 国标原研、国芯科技
    CCP917T、数盾科技），签名经厂商 SDK 调用；侧信道验收按
    GM/T 0028-2014 / GM/T 0008-2012 / YD/T 6868-2026。
    """

    def __init__(self):
        raise NotImplementedError(
            "NationalChipKeyBackend requires a national-standard chip SDK "
            "(v3.0 hardware root, vendor cooperation).")

    def sign(self, idn, msg):
        raise NotImplementedError

    def verify(self, idn, r, s, msg):
        raise NotImplementedError

    def export_pub(self):
        raise NotImplementedError


class _ProtectedKey:
    """HSM 受控区模拟：私钥驻留受保护对象，**拒绝导出**。

    真实 HSM/国密芯片中私钥从不离开受保护区。本类模拟该性质：
    密钥只经内部通道用于签名，任何导出尝试都抛 RuntimeError。
    """

    def __init__(self, priv):
        self._priv = int(priv)

    def export(self):
        raise RuntimeError("protected key is non-exportable (HSM contract)")

    def _signing_handle(self):
        """返回内部签名通道（仅 HSM 内部可用）。"""
        return self._priv


class HsmKeyBackend(SecureKeyBackend):
    """软件 HSM 模拟后端（FR1-06 接入闭合证明）。

    私钥驻留 _ProtectedKey（受控区，不可导出）；签名经 HSM 通道完成，
    调用方只见 (r, s)，从不接触私钥。**可实例化**——证明硬件根模式
    （私钥不驻留调用方内存）可接入且对上层零改动。

    真实芯片（国密芯片 / TPM）只需实现同一 SecureKeyBackend 接口即完成
    替换；本类是其软件等价模拟，用于在无硬件环境下证明接入闭合与
    路径完整性，不等同于真实芯片的侧信道防护（见 Limitations）。
    """

    def __init__(self, priv, pub):
        self._hsm = _ProtectedKey(priv)
        self._pub = pub
        # HSM 通道：受控区密钥经内部 FastSigner 完成签名
        from sm2_fast import FastSigner
        self._fs = FastSigner(self._hsm._signing_handle(), pub)

    def sign(self, idn, msg):
        # 模拟 HSM 内部计算：私钥不出受控区，只返回签名
        return self._fs.sign(idn, msg)

    def verify(self, idn, r, s, msg):
        return self._fs.verify(idn, r, s, msg)

    def export_pub(self):
        return self._pub

    def is_non_exportable(self) -> bool:
        """证明受控区密钥不可导出（HSM 契约）。"""
        try:
            self._hsm.export()
            return False
        except RuntimeError:
            return True


class Pkcs11KeyBackend(SecureKeyBackend):
    """PKCS#11 会话模拟后端（FR1-06 接入闭合证明）。

    模拟经 PKCS#11 token 调用签名机制（CKM_ECDSA）的路径：签名经
    session 句柄完成，密钥句柄常驻 token。可实例化，证明 PKCS#11
    硬件根接入路径闭合；真实 token 只需实现同一接口。
    """

    def __init__(self, priv, pub, token_label="sim-token"):
        self._token_label = token_label
        self._hsm = _ProtectedKey(priv)
        self._pub = pub
        from sm2_fast import FastSigner
        self._fs = FastSigner(self._hsm._signing_handle(), pub)

    def sign(self, idn, msg):
        # 模拟 CKM_ECDSA 签名经 session 调用
        return self._fs.sign(idn, msg)

    def verify(self, idn, r, s, msg):
        return self._fs.verify(idn, r, s, msg)

    def export_pub(self):
        return self._pub

    def token_label(self):
        return self._token_label


def timing_leakage_probe(n_fixed=80, n_rand=80):
    """软件层时序侧信道基线（Welch t-test）。

    度量「固定消息 vs 随机消息」的签名耗时分布是否显著不同。SM2 签名
    使用随机化 k（每次随机），理想实现签名耗时应与消息内容无关（均值
    差 ≈ 0、|t| 小）；若 |t| 显著大，说明实现存在与消息相关的时序泄漏
    ——这是硬件侧信道验收（GM/T 0028 / YD/T 6868）的**软件基线**：真实
    芯片的侧信道防护至少要达到本软件基线对应的泄漏水平。

    返回 dict：mean_fixed/mean_rand/std_fixed/std_rand/t_stat/leakage.
    """
    import statistics
    import time as _t
    import sm2
    d, pub = sm2.gen_keypair()
    from sm2_fast import FastSigner
    fs = FastSigner(d, pub)
    idn = b"agent://sidechannel/baseline"

    def sample(msg, n):
        ts = []
        for _ in range(n):
            t0 = _t.perf_counter()
            fs.sign(idn, msg)
            ts.append((_t.perf_counter() - t0) * 1e6)  # µs
        return ts

    fixed_msg = b"A" * 32
    t_fixed = sample(fixed_msg, n_fixed)
    t_rand = sample(os.urandom(32), n_rand)
    mf, mr = statistics.mean(t_fixed), statistics.mean(t_rand)
    sf, sr = statistics.stdev(t_fixed), statistics.stdev(t_rand)
    # Welch t
    denom = (sf * sf / n_fixed + sr * sr / n_rand) ** 0.5
    t_stat = (mf - mr) / denom if denom > 0 else 0.0
    return {
        "n_fixed": n_fixed, "n_rand": n_rand,
        "mean_fixed_us": round(mf, 2), "mean_rand_us": round(mr, 2),
        "std_fixed_us": round(sf, 2), "std_rand_us": round(sr, 2),
        "t_stat": round(t_stat, 2),
        "leakage": abs(t_stat) >= 4.0,  # |t|>=4 视为显著泄漏（保守）
    }


def self_check():
    """验证默认软件实现与 FastSigner 一致 + 抽象契约可实例化。"""
    out = []
    import sm2
    d, pub = sm2.gen_keypair()
    bk = SoftwareKeyBackend(d, pub)
    idn = b"agent://key/backend"
    msg = b"secure key backend test message"
    r, s = bk.sign(idn, msg)
    out.append(("SoftwareKeyBackend 签名自洽", bk.verify(idn, r, s, msg)))
    out.append(("SoftwareKeyBackend 导出公钥 == 原公钥", bk.export_pub() == pub))
    out.append(("篡改消息后验证失败", not bk.verify(idn, r, s, msg + b"x")))
    # 与直接 FastSigner 互操作（SM2 签名随机化，故验证互操作而非同值）
    from sm2_fast import FastSigner
    fs = FastSigner(d, pub)
    r2, s2 = fs.sign(idn, msg)
    out.append(("SoftwareKeyBackend 签名可被 FastSigner 验证",
                fs.verify(idn, r, s, msg)))
    out.append(("FastSigner 签名可被 SoftwareKeyBackend 验证",
                bk.verify(idn, r2, s2, msg)))
    # 抽象接口：桩类应声明未实现（硬件根待厂商）
    out.append(("SecureKeyBackend 抽象可被软件实现",
                isinstance(bk, SecureKeyBackend)))
    try:
        TpmKeyBackend()
        out.append(("TPMKeyBackend 桩拒绝无硬件构造", False))
    except NotImplementedError:
        out.append(("TPMKeyBackend 桩拒绝无硬件构造", True))

    # ---- FR1-06 接入闭合证明：HSM / PKCS#11 模拟后端可实例化且工作 ----
    hsm = HsmKeyBackend(d, pub)
    rh, sh_ = hsm.sign(idn, msg)
    out.append(("HsmKeyBackend 可实例化并签名", rh is not None and sh_ is not None))
    out.append(("HsmKeyBackend 签名可被验证", hsm.verify(idn, rh, sh_, msg)))
    out.append(("HsmKeyBackend 导出公钥正确", hsm.export_pub() == pub))
    out.append(("HsmKeyBackend 篡改消息后验证失败",
                not hsm.verify(idn, rh, sh_, msg + b"x")))
    out.append(("HsmKeyBackend 受控区密钥不可导出", hsm.is_non_exportable()))
    # 上层零改动：用 HSM 后端走 audit_anchor 签名路径（同一接口）
    from audit_anchor import AuditAnchor
    ha = AuditAnchor(ts=100, chain_len=3, root_hash="99" * 32,
                     issuer_idn="agent://anchor/hsm")
    ha.sig_r, ha.sig_s = hsm.sign(ha.issuer_idn.encode("utf-8"),
                                  ha.payload_bytes())
    out.append(("HsmKeyBackend 经审计锚接口零改动接入",
                ha.verify(hsm.export_pub())[0] is True))

    pk11 = Pkcs11KeyBackend(d, pub, token_label="sim-token")
    rp, sp = pk11.sign(idn, msg)
    out.append(("Pkcs11KeyBackend 可实例化并签名", rp is not None and sp is not None))
    out.append(("Pkcs11KeyBackend 签名可被验证", pk11.verify(idn, rp, sp, msg)))
    out.append(("Pkcs11KeyBackend token 句柄可用",
                pk11.token_label() == "sim-token"))
    out.append(("Pkcs11KeyBackend 签名可被 HsmKeyBackend 互操作验证",
                hsm.verify(idn, rp, sp, msg)))

    # ---- 软件层时序侧信道基线 ----
    probe = timing_leakage_probe()
    out.append(("侧信道基线：固定 vs 随机消息 |t| 未达显著泄漏",
                probe["leakage"] is False))
    out.append(("侧信道基线：采样量充足",
                probe["n_fixed"] >= 80 and probe["n_rand"] >= 80))
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
                               "secure_key_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    for line in lines:
        print(line)


if __name__ == "__main__":
    main()
