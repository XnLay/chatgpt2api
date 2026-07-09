const { webcrypto } = require("crypto");
const vm = require("vm");

function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", (chunk) => {
      data += chunk;
    });
    process.stdin.on("end", () => resolve(data));
    process.stdin.on("error", reject);
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms | 0)));
}

function decodeBase64Text(value) {
  try {
    return Buffer.from(String(value || ""), "base64").toString("utf8");
  } catch {
    return "";
  }
}

function looksLikeEncodedError(value) {
  return /^\d+:\s(?:[A-Za-z]+Error|Error)\b/.test(decodeBase64Text(value));
}

function exposeInternals(sdkSource) {
  const needle = "return Yn?function(){";
  if (!String(sdkSource || "").includes(needle)) {
    throw new Error("sentinel_sdk_patch_failed");
  }
  return String(sdkSource).replace(
    needle,
    "t.__internals={P,ce,D,Nt,_n,jt};return Yn?function(){",
  );
}

function makeCookieJar(seed = "") {
  const map = new Map();
  for (const part of String(seed || "").split(/;\s*/)) {
    if (!part) continue;
    const idx = part.indexOf("=");
    if (idx <= 0) continue;
    map.set(part.slice(0, idx), part.slice(idx + 1));
  }
  return {
    get cookie() {
      return [...map.entries()].map(([k, v]) => `${k}=${v}`).join("; ");
    },
    set cookie(value) {
      const first = String(value || "").split(";", 1)[0];
      const idx = first.indexOf("=");
      if (idx <= 0) return;
      map.set(first.slice(0, idx), first.slice(idx + 1));
    },
  };
}

function createSandbox({ sdkUrl, deviceId, userAgent, locationUrl }) {
  const cookies = makeCookieJar(`oai-did=${deviceId}`);
  const document = {
    currentScript: { src: sdkUrl },
    scripts: [{ src: sdkUrl }],
    body: { appendChild() {}, addEventListener() {}, removeEventListener() {} },
    documentElement: { getAttribute() { return ""; } },
    location: new URL(locationUrl),
    createElement(tag) {
      return {
        tagName: tag,
        style: {},
        addEventListener() {},
        removeEventListener() {},
        contentWindow: { postMessage() {} },
      };
    },
    addEventListener() {},
    removeEventListener() {},
    get cookie() {
      return cookies.cookie;
    },
    set cookie(value) {
      cookies.cookie = value;
    },
  };

  const performanceObj = {
    now: () => Date.now() % 1000000,
    timeOrigin: Date.now() - 5000,
    memory: { jsHeapSizeLimit: 1024 * 1024 * 1024 },
  };
  const navigatorObj = {
    userAgent,
    language: "en-US",
    languages: ["en-US", "en"],
    hardwareConcurrency: 8,
  };
  const windowObj = {
    top: null,
    location: new URL(locationUrl),
    addEventListener() {},
    removeEventListener() {},
    requestIdleCallback(fn) {
      return setTimeout(() => fn({ timeRemaining: () => 10, didTimeout: false }), 0);
    },
    Math,
    Reflect,
    Date,
    Object,
    chrome: {},
    localStorage: {},
    sessionStorage: {},
    performance: performanceObj,
    navigator: navigatorObj,
    document,
    fetch: async () => ({ json: async () => ({}) }),
  };
  windowObj.top = windowObj;
  windowObj.window = windowObj;
  windowObj.self = windowObj;

  const sandbox = {
    console,
    setTimeout,
    clearTimeout,
    TextEncoder,
    URL,
    URLSearchParams,
    atob: (value) => Buffer.from(String(value || ""), "base64").toString("binary"),
    btoa: (value) => Buffer.from(String(value || ""), "binary").toString("base64"),
    crypto: webcrypto,
    performance: performanceObj,
    navigator: navigatorObj,
    screen: { width: 1920, height: 1080 },
    document,
    window: windowObj,
    self: windowObj,
    globalThis: null,
    fetch: windowObj.fetch,
  };
  sandbox.globalThis = sandbox;
  windowObj.globalThis = sandbox;
  return vm.createContext(sandbox);
}

async function loadSdkContext(payload) {
  const sdkSource = exposeInternals(payload.sdk_source);
  const ctx = createSandbox({
    sdkUrl: payload.sdk_url,
    deviceId: payload.device_id,
    userAgent: payload.user_agent || "Mozilla/5.0",
    locationUrl: payload.location_url || "https://auth.openai.com/about-you",
  });
  vm.runInContext(sdkSource, ctx, { timeout: 15000 });
  const sdk = ctx.SentinelSDK;
  if (!sdk || !sdk.__internals) {
    throw new Error("sentinel_sdk_not_initialized");
  }
  return { ctx, sdk, internals: sdk.__internals };
}

async function runPrepare(payload) {
  const { internals } = await loadSdkContext(payload);
  const prepareToken = await internals.P.getRequirementsToken();
  return { prepare_token: String(prepareToken || "") };
}

async function runArtifacts(payload) {
  const { internals } = await loadSdkContext(payload);
  const reqData = payload.req_data || {};
  const prepareToken = String(payload.prepare_token || "");
  const flow = String(payload.flow || "");
  if (!prepareToken) {
    throw new Error("missing_prepare_token");
  }
  if (!reqData || typeof reqData !== "object") {
    throw new Error("missing_req_data");
  }

  internals.D(reqData, prepareToken);

  let collectorError = "";
  if (reqData.so?.required && reqData.so?.collector_dx) {
    const collectorResult = await internals.jt(reqData.so.collector_dx, prepareToken);
    if (looksLikeEncodedError(collectorResult)) {
      collectorError = decodeBase64Text(collectorResult).slice(0, 500);
    } else if (payload.observer_timeout_ms) {
      await sleep(payload.observer_timeout_ms);
    }
  }

  const proofToken = await internals.P.getEnforcementToken(reqData);
  const turnstileToken = reqData.turnstile?.dx ? await internals._n(reqData, reqData.turnstile.dx) : null;
  const token = internals.ce(
    {
      p: proofToken,
      t: turnstileToken,
      c: reqData.token || "",
    },
    flow,
  );

  let soToken = "";
  let soError = collectorError;
  if (!soError && reqData.so?.required && reqData.so?.snapshot_dx) {
    const soRaw = await internals.Nt(reqData.so.snapshot_dx);
    if (looksLikeEncodedError(soRaw)) {
      soError = decodeBase64Text(soRaw).slice(0, 500);
    } else if (soRaw) {
      soToken = internals.ce(
        reqData.token ? { so: soRaw, c: reqData.token } : { so: soRaw },
        flow,
      );
    }
  }

  return {
    token: String(token || ""),
    so_token: String(soToken || ""),
    proof_token: String(proofToken || ""),
    turnstile_token: String(turnstileToken || ""),
    collector_error: collectorError,
    so_error: soError,
  };
}

(async () => {
  const raw = await readStdin();
  const payload = raw ? JSON.parse(raw) : {};
  const mode = String(payload.mode || "").trim();
  let result;
  if (mode === "prepare") {
    result = await runPrepare(payload);
  } else if (mode === "artifacts") {
    result = await runArtifacts(payload);
  } else {
    throw new Error(`unsupported_mode:${mode}`);
  }
  process.stdout.write(JSON.stringify(result));
})().catch((error) => {
  process.stderr.write(String(error?.stack || error?.message || error || "unknown_error"));
  process.exit(1);
});
