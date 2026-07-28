import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ═══════════════════════════════════════════════════════════
// 从 worker.js 中提取的 fetchWithTimeout 逻辑（第2710-2717行）
// ═══════════════════════════════════════════════════════════

async function fetchWithTimeout(url, options, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('FETCH_TIMEOUT')), timeoutMs);
    fetch(url, options)
      .then(res => { clearTimeout(timer); resolve(res); })
      .catch(err => { clearTimeout(timer); reject(err); });
  });
}

// ═══════════════════════════════════════════════════════════
// 测试用例
// ═══════════════════════════════════════════════════════════

describe('fetchWithTimeout - 带超时的 fetch', () => {
  const mockResponse = { ok: true, status: 200 };

  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.useRealTimers();
  });

  it('正常响应不超时，返回响应对象', async () => {
    // 让 fetch 在调用时立即 resolve
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      return Promise.resolve(mockResponse);
    });

    const promise = fetchWithTimeout('https://api.example.com/data', {}, 5000);
    const result = await promise;

    expect(result).toBe(mockResponse);
    expect(globalThis.fetch).toHaveBeenCalledWith('https://api.example.com/data', {});
  });

  it('超时后抛出 FETCH_TIMEOUT 错误', async () => {
    // 让 fetch 永远不 resolve（模拟网络卡住）
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      return new Promise(() => {}); // never resolves
    });

    const promise = fetchWithTimeout('https://api.example.com/slow', {}, 1000);

    // 推进时间超过超时阈值
    vi.advanceTimersByTime(1001);

    // 等待 promise 被 reject
    await expect(promise).rejects.toThrow('FETCH_TIMEOUT');
  });

  it('fetch 网络错误时直接传递错误', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      return Promise.reject(new Error('Network error'));
    });

    const promise = fetchWithTimeout('https://api.example.com/fail', {}, 5000);
    await expect(promise).rejects.toThrow('Network error');
  });

  it('fetch 在超时前完成则清除定时器，不会触发超时', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      return Promise.resolve(mockResponse);
    });

    const clearTimeoutSpy = vi.spyOn(globalThis, 'clearTimeout');

    const promise = fetchWithTimeout('https://api.example.com/fast', {}, 10000);
    const result = await promise;

    expect(result).toBe(mockResponse);
    expect(clearTimeoutSpy).toHaveBeenCalled();

    // 即使再推进时间，超时也不会触发（因为 timer 已被清除）
    vi.advanceTimersByTime(20000);
    // promise 已经 resolved，再次 await 不会抛错
    await promise;
  });

  it('短超时阈值也能正确触发', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(() => {
      return new Promise(() => {}); // never resolves
    });

    const promise = fetchWithTimeout('https://api.example.com/slow', {}, 1);
    vi.advanceTimersByTime(2);

    await expect(promise).rejects.toThrow('FETCH_TIMEOUT');
  });
});
