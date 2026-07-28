import { describe, it, expect, vi, beforeEach } from 'vitest';

// ═══════════════════════════════════════════════════════════
// 模拟 D1 数据库，用 Map 存储记录
// ═══════════════════════════════════════════════════════════
function createMockDB() {
  const store = new Map(); // key -> [{ ip, endpoint, created_at_ms }]

  function prepare(sql) {
    let params = [];
    return {
      bind(...args) {
        params = args;
        return this;
      },
      async first() {
        // SELECT COUNT(*) as cnt FROM api_rate_limits WHERE ip = ? AND endpoint = ? AND created_at_ms >= ?
        const ip = params[0];
        const endpoint = params[1];
        const windowStart = params[2];
        const records = store.get(`${ip}:${endpoint}`) || [];
        const cnt = records.filter(r => r.created_at_ms >= windowStart).length;
        return { cnt };
      },
      async all() {
        return { results: [] };
      },
      async run() {
        if (sql.startsWith('INSERT')) {
          const ip = params[0];
          const endpoint = params[1];
          const now = params[2];
          const key = `${ip}:${endpoint}`;
          if (!store.has(key)) store.set(key, []);
          store.get(key).push({ ip, endpoint, created_at_ms: now });
        } else if (sql.startsWith('DELETE')) {
          const cleanupBefore = params[0];
          for (const [k, records] of store.entries()) {
            store.set(k, records.filter(r => r.created_at_ms >= cleanupBefore));
          }
        }
      },
    };
  }

  return { _store: store, prepare };
}

// ═══════════════════════════════════════════════════════════
// checkRateLimitD1 的测试复刻版本
// 逻辑与 worker.js 完全一致
// ═══════════════════════════════════════════════════════════
async function checkRateLimitD1(env, ip, endpoint, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();
  const windowStart = now - windowMs;

  try {
    const result = await env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM api_rate_limits WHERE ip = ? AND endpoint = ? AND created_at_ms >= ?"
    ).bind(ip, endpoint, windowStart).first();

    if (result && result.cnt >= maxRequests) {
      return false;
    }

    await env.DB.prepare(
      "INSERT INTO api_rate_limits (ip, endpoint, created_at_ms) VALUES (?, ?, ?)"
    ).bind(ip, endpoint, now).run();

    return true;
  } catch (e) {
    return true;
  }
}

// ═══════════════════════════════════════════════════════════
// 测试用例
// ═══════════════════════════════════════════════════════════

describe('checkRateLimitD1 - D1 持久化速率限制', () => {
  let db;

  beforeEach(() => {
    db = createMockDB();
    vi.useFakeTimers();
  });

  it('窗口内未超限时返回 true', async () => {
    const env = { DB: db };
    const result = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', 10, 60000);
    expect(result).toBe(true);
  });

  it('连续请求未超限时全部返回 true', async () => {
    const env = { DB: db };
    for (let i = 0; i < 5; i++) {
      const result = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', 10, 60000);
      expect(result).toBe(true);
    }
    const records = db._store.get('1.2.3.4:/api/chat');
    expect(records).toHaveLength(5);
  });

  it('窗口内超限后返回 false', async () => {
    const env = { DB: db };
    const maxRequests = 3;

    for (let i = 0; i < maxRequests; i++) {
      const result = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, 60000);
      expect(result).toBe(true);
    }

    const blocked = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, 60000);
    expect(blocked).toBe(false);
  });

  it('窗口过期后重置计数，请求应通过', async () => {
    const env = { DB: db };
    const maxRequests = 2;
    const windowMs = 60000;

    await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, windowMs);
    await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, windowMs);

    const blocked = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, windowMs);
    expect(blocked).toBe(false);

    vi.advanceTimersByTime(60001);

    const allowed = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, windowMs);
    expect(allowed).toBe(true);
  });

  it('不同 IP 的请求互相独立', async () => {
    const env = { DB: db };
    const maxRequests = 1;

    const a1 = await checkRateLimitD1(env, '10.0.0.1', '/api/chat', maxRequests, 60000);
    expect(a1).toBe(true);
    const a2 = await checkRateLimitD1(env, '10.0.0.1', '/api/chat', maxRequests, 60000);
    expect(a2).toBe(false);

    const b1 = await checkRateLimitD1(env, '10.0.0.2', '/api/chat', maxRequests, 60000);
    expect(b1).toBe(true);
  });

  it('不同端点的请求互相独立', async () => {
    const env = { DB: db };
    const maxRequests = 1;

    const r1 = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, 60000);
    expect(r1).toBe(true);
    const r2 = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', maxRequests, 60000);
    expect(r2).toBe(false);

    const r3 = await checkRateLimitD1(env, '1.2.3.4', '/api/analysis', maxRequests, 60000);
    expect(r3).toBe(true);
  });

  it('D1 查询异常时降级为允许通过', async () => {
    const failingDb = {
      prepare() {
        let params = [];
        return {
          bind(...args) { params = args; return this; },
          async first() { throw new Error('D1 connection lost'); },
          async run() {},
        };
      },
    };
    const env = { DB: failingDb };
    const result = await checkRateLimitD1(env, '1.2.3.4', '/api/chat', 10, 60000);
    expect(result).toBe(true);
  });
});
