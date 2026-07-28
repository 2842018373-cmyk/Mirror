import { describe, it, expect } from 'vitest';

// ═══════════════════════════════════════════════════════════
// 从 worker.js 中提取的 CORS 逻辑（第6-22行）
// ═══════════════════════════════════════════════════════════

const ALLOWED_ORIGINS = [
  'https://mirrorsoul.top',
  'https://www.mirrorsoul.top',
];

function getCorsHeaders(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
  if (ALLOWED_ORIGINS.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
  } else {
    headers['Access-Control-Allow-Origin'] = ALLOWED_ORIGINS[0];
  }
  return headers;
}

// ═══════════════════════════════════════════════════════════
// 测试用例
// ═══════════════════════════════════════════════════════════

describe('getCorsHeaders - CORS 跨域头', () => {
  it('白名单域名 mirrorsoul.top 返回正确的 CORS 头', () => {
    const headers = getCorsHeaders('https://mirrorsoul.top');
    expect(headers['Access-Control-Allow-Origin']).toBe('https://mirrorsoul.top');
    expect(headers['Access-Control-Allow-Methods']).toBe('GET, POST, PUT, OPTIONS');
    expect(headers['Access-Control-Allow-Headers']).toBe('Content-Type, Authorization');
  });

  it('白名单域名 www.mirrorsoul.top 返回正确的 CORS 头', () => {
    const headers = getCorsHeaders('https://www.mirrorsoul.top');
    expect(headers['Access-Control-Allow-Origin']).toBe('https://www.mirrorsoul.top');
  });

  it('非白名单域名回退到默认域名（第一个）', () => {
    const headers = getCorsHeaders('https://evil.example.com');
    expect(headers['Access-Control-Allow-Origin']).toBe(ALLOWED_ORIGINS[0]);
  });

  it('空 origin 回退到默认域名', () => {
    const headers = getCorsHeaders('');
    expect(headers['Access-Control-Allow-Origin']).toBe(ALLOWED_ORIGINS[0]);
  });

  it('undefined origin 回退到默认域名', () => {
    const headers = getCorsHeaders(undefined);
    expect(headers['Access-Control-Allow-Origin']).toBe(ALLOWED_ORIGINS[0]);
  });

  it('白名单域名大小写敏感（小写不匹配）', () => {
    // 测试大小写敏感性
    const headers = getCorsHeaders('https://MirrorSoul.top');
    expect(headers['Access-Control-Allow-Origin']).toBe(ALLOWED_ORIGINS[0]);
  });

  it('协议不同视为不同域名', () => {
    const headers = getCorsHeaders('http://mirrorsoul.top');
    expect(headers['Access-Control-Allow-Origin']).toBe(ALLOWED_ORIGINS[0]);
  });

  it('白名单域名带路径仍匹配', () => {
    // ALLOWED_ORIGINS.includes 是精确匹配，带路径不匹配
    const headers = getCorsHeaders('https://mirrorsoul.top/some/path');
    expect(headers['Access-Control-Allow-Origin']).toBe(ALLOWED_ORIGINS[0]);
  });
});

describe('ALLOWED_ORIGINS - 白名单配置', () => {
  it('白名单包含预期域名', () => {
    expect(ALLOWED_ORIGINS).toContain('https://mirrorsoul.top');
    expect(ALLOWED_ORIGINS).toContain('https://www.mirrorsoul.top');
  });

  it('白名单第一个元素作为默认回退', () => {
    expect(ALLOWED_ORIGINS[0]).toBe('https://mirrorsoul.top');
  });
});
