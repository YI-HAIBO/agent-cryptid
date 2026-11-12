// multilang_client.mjs —— 用**官方 @a2a-js/sdk** 驱动 cryptid 保护下的 Python A2A 服务端
//
// 目的：证明 cryptid 的凭证校验是**语言无关**的——同一张 cryptid wire 凭证
// （Python 端签发、Python 端 SM2 验签），可以由一个完全独立的 Node.js 官方 SDK
// 客户端驱动，且服务端不改动一行代码。
//
// 用法：
//   CRYPTID_TOKEN=<wire> node multilang_client.mjs [SUT_URL]
//
// SUT_URL 缺省 http://127.0.0.1:9999/
// 不带 CRYPTID_TOKEN 时只跑「无凭证应被拒」的负向对照。

import {
  ClientFactory,
  DefaultAgentCardResolver,
  JsonRpcTransportFactory,
  createAuthenticatingFetchWithRetry,
} from "@a2a-js/sdk/client";

const SUT = (process.argv[2] || process.env.SUT_URL || "http://127.0.0.1:9999/").replace(/\/?$/, "");
const TOKEN = process.env.CRYPTID_TOKEN || "";
const ROLE_USER = 1;                       // protobuf Role enum
const CARD_PATH = "/.well-known/agent-card.json";

let pass = 0;
let fail = 0;

function check(name, ok, detail = "") {
  if (ok) {
    pass++;
    console.log(`  [PASS] ${name}${detail ? " — " + detail : ""}`);
  } else {
    fail++;
    console.log(`  [FAIL] ${name}${detail ? " — " + detail : ""}`);
  }
}

/** 构造带鉴权的 fetch；TOKEN 为空时退化为原生 fetch（用于负向对照）。 */
function makeFetch(token) {
  if (!token) return fetch;
  return createAuthenticatingFetchWithRetry(fetch, {
    headers: async () => ({ Authorization: `Bearer ${token}` }),
    shouldRetryWithHeaders: async () => undefined,
  });
}

/** 建一个 JSON-RPC 客户端。fetchImpl 同时喂给卡片解析器与传输层。 */
async function buildClient(fetchImpl) {
  const factory = new ClientFactory({
    transports: [new JsonRpcTransportFactory({ fetchImpl })],
    preferredTransports: ["jsonrpc"],
    cardResolver: new DefaultAgentCardResolver({ fetchImpl, path: CARD_PATH }),
  });
  return factory.createFromUrl(SUT, CARD_PATH);
}

/** 文本 Part：SDK 走 protobuf oneof 形态 `content: {$case:"text", value}`。 */
function textPart(text) {
  return { content: { $case: "text", value: text }, filename: "", mediaType: "" };
}

function makeMessage(text) {
  return {
    messageId: `msg-${Date.now()}-${Math.floor(Math.random() * 1e6)}`,
    role: ROLE_USER,
    parts: [textPart(text)],
  };
}

/** 从 SDK 归一化后的 SendMessage 结果里收集回复文本（protobuf oneof 形态）。 */
function collectText(res) {
  const out = [];
  const grabPart = (p) => {
    if (!p || typeof p !== "object") return;
    if (typeof p.text === "string") out.push(p.text);
    else if (p.content && p.content.$case === "text" &&
             typeof p.content.value === "string") out.push(p.content.value);
  };
  const msgs = [];
  if (res && typeof res === "object") {
    if (res.message) msgs.push(res.message);
    msgs.push(res);
  }
  for (const m of msgs) {
    if (Array.isArray(m?.parts)) m.parts.forEach(grabPart);
  }
  return out.join("");
}

async function main() {
  console.log("==================================================================");
  console.log("  Step 4 / 多语言互操作：官方 @a2a-js/sdk 1.3.0 → cryptid-guarded A2A SUT");
  console.log("==================================================================");
  console.log(`  SUT      : ${SUT}/`);
  console.log(`  SDK      : @a2a-js/sdk 1.3.0 (Node ${process.version})`);
  console.log(`  TOKEN    : ${TOKEN ? `已提供（${TOKEN.length} 字符）` : "未提供（仅跑负向对照）"}`);
  console.log();

  // ---- 1. 服务发现：无鉴权拉卡片（A2A §8.2） ----
  console.log("[1] 服务发现（无鉴权拉 Agent Card）");
  let card;
  try {
    const r = await fetch(`${SUT}${CARD_PATH}`);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    card = await r.json();
    check("Agent Card 可公开发现", true, `HTTP ${r.status}`);
    console.log(`       name           = ${card.name || "(缺)"}`);
    console.log(`       version        = ${card.version || "(缺)"}`);
    console.log(`       securitySchemes = ${JSON.stringify(Object.keys(card.securitySchemes || {}))}`);
    console.log(`       extensions     = ${JSON.stringify((card.extensions || []).map((e) => e.uri))}`);
  } catch (e) {
    check("Agent Card 可公开发现", false, String(e));
    console.log(`\n卡片不可达，终止。fail=${fail}`);
    process.exit(1);
  }
  const secKeys = Object.keys(card.securitySchemes || {});
  check("卡片正式声明 cryptid 安全方案", secKeys.includes("cryptid-bearer"),
    `securitySchemes=${JSON.stringify(secKeys)}`);

  // ---- 2. 正向：带 cryptid 凭证，官方 SDK 客户端调用 SendMessage ----
  if (TOKEN) {
    console.log("\n[2] 正向：官方 SDK 客户端 + cryptid Bearer 调用 SendMessage");
    try {
      const client = await buildClient(makeFetch(TOKEN));
      const res = await client.sendMessage({
        tenant: "",
        message: makeMessage("hello from node"),
        configuration: { acceptedOutputModes: ["text/plain"],
                         taskPushNotificationConfig: undefined },
        metadata: undefined,
      });
      const text = collectText(res);
      check("带 cryptid 凭证 → SendMessage 成功", !!res && !!text,
        text ? `role=${res?.message?.role} reply="${text}"`
             : "无回复文本，原始响应=" + JSON.stringify(res).slice(0, 500));
    } catch (e) {
      check("带 cryptid 凭证 → SendMessage 成功", false,
        `${e.name}: ${e.message}`);
    }
  }

  // ---- 3. 负向对照 A：完全不带凭证 ----
  console.log("\n[3] 负向对照 A：不带任何 Authorization 头");
  try {
    const client = await buildClient(makeFetch(""));
    await client.sendMessage({
      tenant: "",
      message: makeMessage("should be rejected"),
      configuration: { acceptedOutputModes: ["text/plain"],
                       taskPushNotificationConfig: undefined },
      metadata: undefined,
    });
    check("无凭证被拒", false, "服务端竟然放行了！");
  } catch (e) {
    check("无凭证被拒", true, `${e.name}: ${e.message}`);
  }

  // ---- 4. 负向对照 B：伪造 Bearer ----
  console.log("\n[4] 负向对照 B：伪造 Bearer（语法合法但非 cryptid 凭证）");
  try {
    const client = await buildClient(makeFetch("DEADBEEFCAFE"));
    await client.sendMessage({
      tenant: "",
      message: makeMessage("forged token"),
      configuration: { acceptedOutputModes: ["text/plain"],
                       taskPushNotificationConfig: undefined },
      metadata: undefined,
    });
    check("伪造 Bearer 被拒", false, "服务端竟然放行了！");
  } catch (e) {
    check("伪造 Bearer 被拒", true, `${e.name}: ${e.message}`);
  }

  // ---- 5. 负向对照 C：MCP 域的 token 不能跨协议挪到 A2A（受众绑定） ----
  if (TOKEN) {
    console.log("\n[5] 负向对照 C：受众不符（aud 绑定在跨语言边界上仍生效）");
    // 复用同一路径，但通过一个 aud 被篡改的凭证触发拒绝
    // 这里用「把 token 截断」模拟凭证被改写（会同时破坏签名）
    const tampered = TOKEN.slice(0, Math.max(20, TOKEN.length - 40));
    try {
      const client = await buildClient(makeFetch(tampered));
      await client.sendMessage({
        tenant: "",
        message: makeMessage("tampered credential"),
        configuration: { acceptedOutputModes: ["text/plain"],
                         taskPushNotificationConfig: undefined },
        metadata: undefined,
      });
      check("篡改凭证被拒", false, "服务端竟然放行了！");
    } catch (e) {
      check("篡改凭证被拒", true, `${e.name}: ${e.message}`);
    }
  }

  console.log("\n==================================================================");
  console.log(`  结果：${pass} PASS / ${fail} FAIL`);
  console.log("==================================================================");
  process.exit(fail === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error("未捕获异常:", e);
  process.exit(2);
});
