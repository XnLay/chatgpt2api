/**
 * Cloudflare Worker: chatgpt2api 注册机看门狗
 *
 * 作用：由 Cron Trigger 定时检查 /api/register；如果注册机未运行，则调用 /api/register/start 启动。
 *
 * 必需环境变量：
 * - CHATGPT2API_BASE_URL   例如：https://your-chatgpt2api.example.com
 * - CHATGPT2API_AUTH_TOKEN 项目的管理员 Bearer Token，可使用 CHATGPT2API_AUTH_KEY 或管理员密钥
 *
 * 可选环境变量：
 * - WATCHDOG_TIMEOUT_MS    请求超时毫秒数，默认 15000
 * - MANUAL_TRIGGER_TOKEN   设置后可通过 /check + x-watchdog-token 手动触发一次检查
 */

const DEFAULT_TIMEOUT_MS = 15_000;
const HALF_MINUTE_MS = 30_000;

export default {
  async scheduled(controller, env, ctx) {
    ctx.waitUntil(runHalfMinuteSchedule(env, controller));
  },

  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname !== '/check') {
      return jsonResponse({ ok: true, message: 'register watchdog is alive' });
    }

    // 手动触发默认关闭；需要时设置 MANUAL_TRIGGER_TOKEN，避免公网随意触发。
    if (!env.MANUAL_TRIGGER_TOKEN) {
      return jsonResponse({ ok: false, error: 'manual trigger is disabled' }, 404);
    }
    if (request.headers.get('x-watchdog-token') !== env.MANUAL_TRIGGER_TOKEN) {
      return jsonResponse({ ok: false, error: 'forbidden' }, 403);
    }

    const result = await checkAndStartRegister(env, { source: 'manual' });
    return jsonResponse(result, result.ok ? 200 : 502);
  },
};

async function runHalfMinuteSchedule(env, controller) {
  const first = await checkAndStartRegister(env, { source: 'cron', cron: controller.cron, tick: 0 });
  await sleep(HALF_MINUTE_MS);
  const second = await checkAndStartRegister(env, { source: 'cron', cron: controller.cron, tick: 30 });
  return { first, second };
}

async function checkAndStartRegister(env, context = {}) {
  const baseUrl = normalizeBaseUrl(env.CHATGPT2API_BASE_URL);
  const token = String(env.CHATGPT2API_AUTH_TOKEN || '').trim();
  const timeoutMs = normalizeTimeout(env.WATCHDOG_TIMEOUT_MS);

  if (!baseUrl) {
    return logResult({ ok: false, action: 'skip', error: 'CHATGPT2API_BASE_URL is required', ...context });
  }
  if (!token) {
    return logResult({ ok: false, action: 'skip', error: 'CHATGPT2API_AUTH_TOKEN is required', ...context });
  }

  try {
    const current = await requestJson(`${baseUrl}/api/register`, {
      method: 'GET',
      token,
      timeoutMs,
    });
    const register = current.register || {};

    if (isRegisterRunning(register)) {
      return logResult({
        ok: true,
        action: 'noop',
        running: true,
        enabled: Boolean(register.enabled),
        stats_running: Number(register.stats?.running || 0),
        ...context,
      });
    }

    const started = await requestJson(`${baseUrl}/api/register/start`, {
      method: 'POST',
      token,
      timeoutMs,
    });
    const nextRegister = started.register || {};

    return logResult({
      ok: true,
      action: 'start',
      running: isRegisterRunning(nextRegister),
      enabled: Boolean(nextRegister.enabled),
      stats_running: Number(nextRegister.stats?.running || 0),
      ...context,
    });
  } catch (error) {
    return logResult({
      ok: false,
      action: 'error',
      error: error instanceof Error ? error.message : String(error),
      ...context,
    });
  }
}

function isRegisterRunning(register) {
  return Boolean(register.enabled) || Number(register.stats?.running || 0) > 0;
}

async function requestJson(url, { method, token, timeoutMs }) {
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
    signal: AbortSignal.timeout(timeoutMs),
  });

  const text = await response.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      throw new Error(`${method} ${url} returned non-json HTTP ${response.status}: ${text.slice(0, 200)}`);
    }
  }

  if (!response.ok) {
    throw new Error(`${method} ${url} failed HTTP ${response.status}: ${text.slice(0, 300)}`);
  }
  return data || {};
}

function normalizeBaseUrl(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function normalizeTimeout(value) {
  const parsed = Number(value || DEFAULT_TIMEOUT_MS);
  return Number.isFinite(parsed) && parsed > 0 ? Math.min(parsed, 60_000) : DEFAULT_TIMEOUT_MS;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function logResult(result) {
  console.log(JSON.stringify({ event: 'register_watchdog', ...result }));
  return result;
}
