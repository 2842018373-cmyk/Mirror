// ══════════════════════════════════════════ Mirror API Worker v3 ══════════════════════════════════════════
// Cloudflare Workers + D1 后端
// v3: 安全加固 + 数据隔离 + 认证系统 + AES加密 + 服务端验证码

// CORS 白名单（仅生产域名，移除测试域名减少攻击面）
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

// 简易速率限制（基于 IP + 端点，内存级，仅用于全局快速拦截）
const rateLimits = new Map();
function checkRateLimit(ip, endpoint, maxRequests = 10, windowMs = 60000) {
  const key = `${ip}:${endpoint}`;
  const now = Date.now();
  const record = rateLimits.get(key);
  if (!record || now - record.startTime > windowMs) {
    rateLimits.set(key, { count: 1, startTime: now });
    return true;
  }
  if (record.count >= maxRequests) {
    return false;
  }
  record.count++;
  return true;
}

// D1 持久化速率限制（防多实例绕过，用于敏感端点：AI调用、认证、房间创建等）
// 原理：每次请求在 api_rate_limits 表中插入一条记录，查询窗口内记录数判断是否超限
async function checkRateLimitD1(env, ip, endpoint, maxRequests = 10, windowMs = 60000) {
  const now = Date.now();
  const windowStart = now - windowMs;

  try {
    // 查询当前窗口内的请求次数
    const result = await env.DB.prepare(
      "SELECT COUNT(*) as cnt FROM api_rate_limits WHERE ip = ? AND endpoint = ? AND created_at_ms >= ?"
    ).bind(ip, endpoint, windowStart).first();

    if (result && result.cnt >= maxRequests) {
      // 记录限流触发日志（异步，不阻塞）
      logSecurityEvent(env, 'rate_limit', { endpoint, maxRequests, windowMs }, ip, endpoint, null, null).catch(() => {});
      return false;
    }

    // 记录本次请求
    await env.DB.prepare(
      "INSERT INTO api_rate_limits (ip, endpoint, created_at_ms) VALUES (?, ?, ?)"
    ).bind(ip, endpoint, now).run();

    // 概率性清理过期记录（1% 概率，避免每次请求都清理）
    if (Math.random() < 0.01) {
      const cleanupBefore = now - 3600000; // 清理1小时前的记录
      await env.DB.prepare("DELETE FROM api_rate_limits WHERE created_at_ms < ?").bind(cleanupBefore).run();
    }

    return true;
  } catch (e) {
    // D1 查询失败时降级为允许通过（不阻断正常请求，但记录错误）
    console.error('checkRateLimitD1 error:', e.message);
    return true;
  }
}

// ══════════════════════════════════════════ 安全中间件 ══════════════════════════════════════════

// 已知恶意 User-Agent 特征
const BLOCKED_UA_PATTERNS = [
  /bot$/i, /crawl/i, /spider/i, /scraper/i, /curl\//i, /python-requests/i,
  /httpclient/i, /wget/i, /nikto/i, /sqlmap/i, /nmap/i, /masscan/i,
  /hydra/i, /dirbuster/i, /gobuster/i,
];

// IP 黑名单（内存级，重启清空）
const ipBlacklist = new Set();

// 全局安全检查（在所有路由之前执行）
function securityCheck(request, env) {
  const path = new URL(request.url).pathname;
  const method = request.method;
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  const ua = request.headers.get('User-Agent') || '';

  // 1. IP 黑名单
  if (ipBlacklist.has(ip)) {
    return { blocked: true, status: 403, reason: 'Forbidden' };
  }

  // 2. User-Agent 过滤
  if (!ua || ua.length < 10) {
    return { blocked: true, status: 403, reason: 'Invalid User-Agent' };
  }
  for (const pattern of BLOCKED_UA_PATTERNS) {
    if (pattern.test(ua) && !ua.includes('Cloudflare')) {
      return { blocked: true, status: 403, reason: 'Blocked User-Agent' };
    }
  }

  // 3. 全局请求体大小限制（100KB）
  const contentLength = parseInt(request.headers.get('Content-Length') || '0');
  if (contentLength > 102400) {
    return { blocked: true, status: 413, reason: 'Request body too large' };
  }

  // 4. 全局 IP 级速率限制（每 IP 每分钟 100 次请求）
  if (!checkRateLimit(ip, '_global', 100, 60000)) {
    return { blocked: true, status: 429, reason: 'Too many requests' };
  }

  // 5. 只允许 GET/POST/PUT/OPTIONS
  if (!['GET', 'POST', 'PUT', 'OPTIONS'].includes(method)) {
    return { blocked: true, status: 405, reason: 'Method not allowed' };
  }

  // 6. 路径遍历防护
  if (path.includes('..') || path.includes('//')) {
    return { blocked: true, status: 400, reason: 'Invalid path' };
  }

  return { blocked: false };
}

// ══════════════════════════════════════════ Cloudflare Turnstile 人机验证 ══════════════════════════════════════════

// 校验 Turnstile token（服务端向 Cloudflare 验证）
async function verifyTurnstile(env, token, ip) {
  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    // 未配置 secret key 时，跳过校验（降级，便于逐步上线）
    return { success: true, skipped: true };
  }
  if (!token) {
    return { success: false, error: '请先完成人机验证' };
  }
  try {
    const resp = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: secret,
        response: token,
        remoteip: ip || '',
      }),
    });
    const data = await resp.json();
    if (data.success) {
      return { success: true };
    }
    return { success: false, error: '人机验证失败，请重试' };
  } catch (e) {
    console.error('Turnstile verify error:', e.message);
    return { success: false, error: '人机验证服务异常' };
  }
}

// ══════════════════════════════════════════ D1 持久化限流（短信发送） ══════════════════════════════════════════

// 检查短信发送频率（基于 D1 持久化，防多实例绕过）
// 限制：同一手机号 60秒冷却 + 每天10次；同一IP 每分钟3次 + 每天20次
async function checkSmsRateLimit(env, phone, ip) {
  const now = Date.now();
  const oneMinAgo = now - 60000;
  const oneDayAgoMs = now - 24 * 60 * 60 * 1000;
  // D1 用 datetime 字符串存储 created_at，转毫秒比较
  const oneDayAgoDate = new Date(oneDayAgoMs).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');

  // 1. 手机号维度
  const phoneToday = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM sms_send_log WHERE phone = ? AND created_at >= ?"
  ).bind(phone, oneDayAgoDate).first();
  if (phoneToday && phoneToday.cnt >= 10) {
    return { allowed: false, reason: '该手机号今日获取验证码次数已达上限（10次），请明日再试', code: 'PHONE_DAILY_LIMIT' };
  }

  // 2. IP 维度 - 每分钟3次
  const ipMin = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM sms_send_log WHERE ip = ? AND created_at_ms >= ?"
  ).bind(ip, oneMinAgo).first();
  if (ipMin && ipMin.cnt >= 3) {
    return { allowed: false, reason: '操作过于频繁，请稍后再试', code: 'IP_MINUTE_LIMIT' };
  }

  // 3. IP 维度 - 每天20次
  const ipToday = await env.DB.prepare(
    "SELECT COUNT(*) as cnt FROM sms_send_log WHERE ip = ? AND created_at >= ?"
  ).bind(ip, oneDayAgoDate).first();
  if (ipToday && ipToday.cnt >= 20) {
    return { allowed: false, reason: '今日请求次数过多，请明日再试', code: 'IP_DAILY_LIMIT' };
  }

  return { allowed: true };
}

// 记录短信发送日志（用于持久化限流）
async function logSmsSend(env, phone, ip) {
  const now = Date.now();
  await env.DB.prepare(
    "INSERT INTO sms_send_log (phone, ip, created_at, created_at_ms) VALUES (?, ?, datetime('now'), ?)"
  ).bind(phone, ip, now).run();
}

// ══════════════════════════════════════════ 服务端验证码 ══════════════════════════════════════════

// 验证码存储（替代前端生成，防机器人刷短信）
const captchaStore = new Map();

function generateCaptcha() {
  const a = Math.floor(Math.random() * 10) + 1;
  const b = Math.floor(Math.random() * 10) + 1;
  const ops = ['+', '-', '×'];
  const op = ops[Math.floor(Math.random() * 3)];
  let answer;
  if (op === '+') answer = a + b;
  else if (op === '-') answer = a - b;
  else answer = a * b;
  const id = 'cp_' + Math.random().toString(36).substr(2, 12);
  captchaStore.set(id, { answer, expireAt: Date.now() + 300000 }); // 5分钟有效
  cleanExpiredCaptchas();
  return { id, question: a + ' ' + op + ' ' + b + ' = ?' };
}

function verifyCaptcha(id, answer) {
  const record = captchaStore.get(id);
  if (!record) return false;
  if (Date.now() > record.expireAt) {
    captchaStore.delete(id);
    return false;
  }
  captchaStore.delete(id); // 一次性使用
  return parseInt(answer) === record.answer;
}

// 惰性清理过期验证码（Cloudflare Workers 不支持 setInterval，在每次操作时顺便清理）
function cleanExpiredCaptchas() {
  const now = Date.now();
  for (const [id, record] of captchaStore) {
    if (now > record.expireAt) captchaStore.delete(id);
  }
}

// ══════════════════════════════════════════ AES-GCM 加密工具 ══════════════════════════════════════════

async function getEncryptionKey(env) {
  const secret = env.ENCRYPTION_KEY || 'mirror-dev-encryption-key-32';
  const keyMaterial = new TextEncoder().encode(secret.padEnd(32, '0').slice(0, 32));
  return await crypto.subtle.importKey('raw', keyMaterial, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptText(env, plaintext) {
  try {
    const key = await getEncryptionKey(env);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
    // 拼接: iv(12字节) + ciphertext
    const combined = new Uint8Array(iv.length + ciphertext.byteLength);
    combined.set(iv, 0);
    combined.set(new Uint8Array(ciphertext), iv.length);
    return btoa(String.fromCharCode(...combined));
  } catch (e) {
    console.error('Encryption failed:', e.message);
    return null;
  }
}

async function decryptText(env, encryptedBase64) {
  try {
    const key = await getEncryptionKey(env);
    const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));
    const iv = combined.slice(0, 12);
    const ciphertext = combined.slice(12);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    // 解密失败可能是旧 Base64 数据，返回 null 让调用方走兼容逻辑
    return null;
  }
}

// ══════════════════════════════════════════ 密码哈希工具 ══════════════════════════════════════════

const DEFAULT_PASSWORD = '1234';

// 生成随机 salt
function generateSalt(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let salt = '';
  const randomValues = crypto.getRandomValues(new Uint8Array(length));
  for (let i = 0; i < length; i++) {
    salt += chars[randomValues[i] % chars.length];
  }
  return salt;
}

// SHA-256 哈希
async function hashPassword(password, salt) {
  const data = new TextEncoder().encode(salt + password);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// 为用户初始化默认密码
async function initUserPassword(env, userId) {
  const salt = generateSalt();
  const hash = await hashPassword(DEFAULT_PASSWORD, salt);
  await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(hash, salt, userId).run();
  return { salt, hash };
}

// 生成 6 位房间码（组合数 10 亿+，防爆破）
function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

// 统一响应
function jsonResponse(data, status = 200, origin) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) },
  });
}

// 安全的角色校验
function validateRole(role) {
  return role === 'a' || role === 'b' ? role : null;
}

// 检查房间是否过期
function isExpired(room) {
  if (!room.expires_at) return true;
  return new Date(room.expires_at) < new Date();
}

// ══════════════════════════════════════════ 阿里云短信工具 ══════════════════════════════════════════

// 阿里云短信 API 签名（HMAC-SHA1，RPC 风格）
async function aliyunSmsSign(params, accessKeySecret) {
  const sortedKeys = Object.keys(params).sort();
  const canonicalizedQueryString = sortedKeys
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
    .join('&');

  const stringToSign = 'GET&%2F&' + encodeURIComponent(canonicalizedQueryString);

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(accessKeySecret + '&'),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(stringToSign));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

// 发送阿里云短信
async function sendAliyunSms(env, phone, templateParam) {
  const accessKeyId = env.ALIYUN_ACCESS_KEY_ID;
  const accessKeySecret = env.ALIYUN_ACCESS_KEY_SECRET;
  const signName = env.SMS_SIGN_NAME;
  const templateCode = env.SMS_TEMPLATE_CODE;

  if (!accessKeyId || !accessKeySecret || !signName || !templateCode) {
    return { success: false, error: '短信服务未配置' };
  }

  const params = {
    Action: 'SendSms',
    Version: '2017-05-25',
    Format: 'JSON',
    AccessKeyId: accessKeyId,
    SignatureMethod: 'HMAC-SHA1',
    SignatureVersion: '1.0',
    SignatureNonce: Math.random().toString(36).slice(2, 16) + Date.now(),
    Timestamp: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    PhoneNumbers: phone,
    SignName: signName,
    TemplateCode: templateCode,
    TemplateParam: JSON.stringify(templateParam),
    RegionId: 'cn-hangzhou',
  };

  const signature = await aliyunSmsSign(params, accessKeySecret);
  params.Signature = signature;

  const queryString = Object.keys(params)
    .map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k]))
    .join('&');

  const url = 'https://dysmsapi.aliyuncs.com/?' + queryString;

  try {
    const resp = await fetch(url, { method: 'GET' });
    const data = await resp.json();
    if (data.Code === 'OK') {
      return { success: true, bizId: data.BizId };
    }
    return { success: false, error: data.Message || data.Code };
  } catch (e) {
    return { success: false, error: e.message };
  }
}

// ══════════════════════════════════════════ JWT 工具函数 ══════════════════════════════════════════

function base64urlEncode(str) {
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return atob(str);
}

// 创建 JWT（HS256，7天过期）
async function createJWT(env, payload) {
  const header = base64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = base64urlEncode(JSON.stringify({
    ...payload,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600,
  }));
  const data = `${header}.${body}`;

  const secret = env.JWT_SECRET || 'mirror-dev-jwt-secret-key';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const signature = base64urlEncode(String.fromCharCode(...new Uint8Array(sig)));

  return `${data}.${signature}`;
}

// 验证 JWT
async function verifyJWT(env, token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');

  const secret = env.JWT_SECRET || 'mirror-dev-jwt-secret-key';
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const sig = new Uint8Array([...base64urlDecode(parts[2])].map(c => c.charCodeAt(0)));
  const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error('Invalid signature');

  const payload = JSON.parse(base64urlDecode(parts[1]));
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');

  return payload;
}

// 统一鉴权辅助函数：从请求头提取 JWT，返回 {uid, user, error}
async function getAuthUser(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return { error: '未登录', code: 'NO_TOKEN' };
  try {
    const payload = await verifyJWT(env, token);
    const user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type FROM users WHERE id = ?').bind(payload.uid).first();
    if (!user) return { error: '用户不存在', code: 'USER_NOT_FOUND' };
    return { uid: payload.uid, user, payload };
  } catch (e) {
    return { error: 'Token无效或已过期', code: 'INVALID_TOKEN' };
  }
}

// ══════════════════════════════════════════ 管理员认证 ══════════════════════════════════════════

// 生成管理员JWT（独立密钥，2小时过期）
async function signAdminJWT(env, payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const body = { ...payload, exp: Math.floor(Date.now() / 1000) + 7200, iat: Math.floor(Date.now() / 1000) };
  const encodedHeader = base64urlEncode(JSON.stringify(header));
  const encodedBody = base64urlEncode(JSON.stringify(body));
  const data = new TextEncoder().encode(`${encodedHeader}.${encodedBody}`);
  const secret = env.ADMIN_JWT_SECRET || env.JWT_SECRET;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, data);
  const sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${encodedHeader}.${encodedBody}.${sigBase64}`;
}

// 验证管理员JWT
async function verifyAdminJWT(env, token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token');
  const secret = env.ADMIN_JWT_SECRET || env.JWT_SECRET;
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sig = new Uint8Array([...base64urlDecode(parts[2])].map(c => c.charCodeAt(0)));
  const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(`${parts[0]}.${parts[1]}`));
  if (!valid) throw new Error('Invalid signature');
  const payload = JSON.parse(base64urlDecode(parts[1]));
  if (payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired');
  return payload;
}

// 检查管理员认证
async function checkAdminAuth(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return { error: '未登录', code: 'NO_TOKEN' };
  try {
    const payload = await verifyAdminJWT(env, token);
    if (payload.role !== 'admin') return { error: '无权访问', code: 'FORBIDDEN' };
    return { admin: payload.sub, payload };
  } catch (e) {
    return { error: '管理员Token无效或已过期', code: 'INVALID_TOKEN' };
  }
}

// 检查IP白名单
async function checkAdminIP(request, env) {
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  try {
    const config = await env.DB.prepare("SELECT config_value FROM admin_config WHERE config_key = 'ip_whitelist'").first();
    if (!config) return { allowed: true, ip }; // 未配置白名单时允许访问
    const whitelist = JSON.parse(config.config_value || '[]');
    if (!Array.isArray(whitelist) || whitelist.length === 0) return { allowed: true, ip };
    if (whitelist.includes(ip)) return { allowed: true, ip };
    return { allowed: false, ip };
  } catch (e) {
    console.error('checkAdminIP error:', e.message);
    return { allowed: true, ip }; // 出错时允许访问（降级）
  }
}

// 获取管理员配置
async function getAdminConfig(env, key, defaultValue) {
  try {
    const row = await env.DB.prepare('SELECT config_value FROM admin_config WHERE config_key = ?').bind(key).first();
    return row ? JSON.parse(row.config_value) : defaultValue;
  } catch (e) {
    return defaultValue;
  }
}

// 设置管理员配置
async function setAdminConfig(env, key, value) {
  const json = JSON.stringify(value);
  await env.DB.prepare(
    "INSERT INTO admin_config (config_key, config_value, updated_at) VALUES (?, ?, datetime('now')) " +
    "ON CONFLICT(config_key) DO UPDATE SET config_value = excluded.config_value, updated_at = datetime('now')"
  ).bind(key, json).run();
}

// ══════════════════════════════════════════ 安全日志 ══════════════════════════════════════════

// 记录安全日志
async function logSecurityEvent(env, eventType, eventDetail, ip, endpoint, userId, adminId) {
  try {
    const detailJson = typeof eventDetail === 'string' ? eventDetail : JSON.stringify(eventDetail);
    await env.DB.prepare(
      "INSERT INTO security_logs (event_type, event_detail, ip, endpoint, user_id, admin_id, created_at) " +
      "VALUES (?, ?, ?, ?, ?, ?, datetime('now'))"
    ).bind(eventType, detailJson, ip || '', endpoint || '', userId || null, adminId || null).run();
  } catch (e) {
    console.error('logSecurityEvent error:', e.message);
  }
}

// ══════════════════════════════════════════ 主处理函数 ══════════════════════════════════════════

export default {
  async fetch(request, env, ctx) {
    const origin = request.headers.get('Origin') || '';
    const corsHeaders = getCorsHeaders(origin);

    // 处理 CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);
    const path = url.pathname;
    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

    // ══════════════════════════════════════════ 全局安全检查 ══════════════════════════════════════════
    const security = securityCheck(request, env);
    if (security.blocked) {
      // 记录恶意请求拦截日志
      const logType = security.status === 429 ? 'rate_limit' : 'malicious_request';
      logSecurityEvent(env, logType, { reason: security.reason, status: security.status, ua: request.headers.get('User-Agent') || '' }, clientIP, path, null, null).catch(() => {});
      return new Response(JSON.stringify({ error: security.reason }), {
        status: security.status,
        headers: { 'Content-Type': 'application/json', ...getCorsHeaders(origin) },
      });
    }

    try {
      // ══════════════════════════════════════════ 验证码 API ══════════════════════════════════════════

      // 获取验证码题目（GET /api/captcha）
      if (path === '/api/captcha' && request.method === 'GET') {
        const captcha = generateCaptcha();
        return jsonResponse({ captchaId: captcha.id, question: captcha.question }, 200, origin);
      }

      // ══════════════════════════════════════════ 认证 API ══════════════════════════════════════════

      // 游客登录（POST /api/auth/guest）
      if (path === '/api/auth/guest' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { guestId } = body;
        if (!guestId || typeof guestId !== 'string' || guestId.length < 10) {
          return jsonResponse({ error: '无效的游客ID' }, 400, origin);
        }

        // 查找或创建用户
        let user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, avatar, created_at FROM users WHERE guest_id = ?').bind(guestId).first();

        if (!user) {
          await env.DB.prepare('INSERT INTO users (guest_id, created_at, last_login_at) VALUES (?, datetime("now"), datetime("now"))').bind(guestId).run();
          user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, avatar, created_at FROM users WHERE guest_id = ?').bind(guestId).first();
        } else {
          await env.DB.prepare('UPDATE users SET last_login_at = datetime("now") WHERE id = ?').bind(user.id).run();
        }

        const token = await createJWT(env, { uid: user.id, gid: guestId, phone: null });
        return jsonResponse({ success: true, token, isGuest: true, user: { id: user.id, phone: null, nickname: user.nickname, avatar: user.avatar || '' } }, 200, origin);
      }

      // 密码登录（POST /api/auth/password-login）
      if (path === '/api/auth/password-login' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'password_login', 10, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { phone, password } = body;
        if (!/^1[3-9]\d{9}$/.test(phone)) {
          return jsonResponse({ error: '手机号格式不正确' }, 400, origin);
        }
        if (!password || password.length < 1 || password.length > 32) {
          return jsonResponse({ error: '请输入密码' }, 400, origin);
        }

        // 查找用户，不存在则自动注册
        let user = await env.DB.prepare('SELECT id, phone, password_hash, password_salt, nickname, mira_type, avatar, guest_id FROM users WHERE phone = ?').bind(phone).first();
        if (!user) {
          // 自动注册：创建用户并设置默认密码
          const salt = generateSalt();
          const hash = await hashPassword(DEFAULT_PASSWORD, salt);
          await env.DB.prepare('INSERT INTO users (phone, password_hash, password_salt, created_at, last_login_at) VALUES (?, ?, ?, datetime("now"), datetime("now"))').bind(phone, hash, salt).run();
          user = await env.DB.prepare('SELECT id, phone, password_hash, password_salt, nickname, mira_type, avatar, guest_id FROM users WHERE phone = ?').bind(phone).first();
        }

        // 如果用户没有密码（老用户），初始化默认密码
        let storedHash = user.password_hash;
        let storedSalt = user.password_salt;
        if (!storedHash || !storedSalt) {
          const result = await initUserPassword(env, user.id);
          storedHash = result.hash;
          storedSalt = result.salt;
        }

        // 校验密码
        const inputHash = await hashPassword(password, storedSalt);
        if (inputHash !== storedHash) {
          return jsonResponse({ error: '密码错误' }, 401, origin);
        }

        // 登录成功，更新最后登录时间
        await env.DB.prepare('UPDATE users SET last_login_at = datetime("now") WHERE id = ?').bind(user.id).run();

        // 生成 JWT
        const token = await createJWT(env, { uid: user.id, gid: user.guest_id || null, phone: user.phone });
        return jsonResponse({
          success: true,
          token,
          isGuest: false,
          user: { id: user.id, phone: user.phone, nickname: user.nickname, avatar: user.avatar || '' }
        }, 200, origin);
      }

      // 发送验证码（POST /api/auth/send-code）
      if (path === '/api/auth/send-code' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'send_code', 10, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { phone, turnstileToken } = body;

        if (!/^1[3-9]\d{9}$/.test(phone)) {
          return jsonResponse({ error: '手机号格式不正确' }, 400, origin);
        }

        // ① Turnstile 人机验证（配置了 secret key 才强制校验）
        const turnstileResult = await verifyTurnstile(env, turnstileToken, clientIP);
        if (!turnstileResult.success) {
          return jsonResponse({ error: turnstileResult.error, needTurnstile: true }, 400, origin);
        }

        // ② D1 持久化限流（手机号每天10次 + IP每分钟3次/每天20次，防多实例绕过）
        const rateResult = await checkSmsRateLimit(env, phone, clientIP);
        if (!rateResult.allowed) {
          return jsonResponse({ error: rateResult.reason, code: rateResult.code }, 429, origin);
        }

        // ③ 检查60秒冷却（基于 verify_codes 表）
        const existing = await env.DB.prepare('SELECT created_at FROM verify_codes WHERE phone = ?').bind(phone).first();
        if (existing) {
          const elapsed = Date.now() - new Date(existing.created_at).getTime();
          if (elapsed < 60000) {
            return jsonResponse({ error: '请稍后再试', remainSeconds: Math.ceil((60000 - elapsed) / 1000) }, 429, origin);
          }
        }

        // 生成6位验证码
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expireAt = Date.now() + 5 * 60 * 1000; // 5分钟

        // 写入D1
        try {
          await env.DB.prepare(
            'INSERT OR REPLACE INTO verify_codes (phone, code, expire_at, attempts, created_at) VALUES (?, ?, ?, 0, datetime("now"))'
          ).bind(phone, code, expireAt).run();
        } catch (dbErr) {
          console.error('D1 Insert error:', dbErr.message, 'Phone:', phone);
          return jsonResponse({ error: '系统繁忙，请稍后重试' }, 500, origin);
        }

        // 调用阿里云短信API发送
        const smsResult = await sendAliyunSms(env, phone, { code });
        if (!smsResult.success) {
          console.error('SMS send failed:', smsResult.error, 'Phone:', phone);
          if (smsResult.error === '短信服务未配置') {
            console.log(`[SMS-DEV] 验证码: ${code}, 手机号: ${phone}`);
            return jsonResponse({ success: true, expireIn: 300, devCode: code }, 200, origin);
          }
          return jsonResponse({ error: '短信发送失败，请稍后重试' }, 500, origin);
        }

        // ④ 记录发送日志（用于持久化限流统计）
        try {
          await logSmsSend(env, phone, clientIP);
        } catch (logErr) {
          console.error('SMS log error:', logErr.message);
        }

        return jsonResponse({ success: true, expireIn: 300 }, 200, origin);
      }

      // 短信验证码登录/注册（POST /api/auth/sms-login）
      if (path === '/api/auth/sms-login' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'sms_login', 10, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { phone, code } = body;
        if (!/^1[3-9]\d{9}$/.test(phone)) {
          return jsonResponse({ error: '手机号格式不正确' }, 400, origin);
        }
        if (!code || code.length !== 6) {
          return jsonResponse({ error: '请输入6位验证码' }, 400, origin);
        }

        // 查验证码
        const record = await env.DB.prepare('SELECT * FROM verify_codes WHERE phone = ?').bind(phone).first();
        if (!record) {
          return jsonResponse({ error: '请先获取验证码' }, 400, origin);
        }

        if (Date.now() > record.expire_at) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();
          return jsonResponse({ error: '验证码已过期，请重新获取' }, 400, origin);
        }

        // 错误次数检查
        const newAttempts = (record.attempts || 0) + 1;
        if (newAttempts > 5) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();
          return jsonResponse({ error: '尝试次数过多，请重新获取验证码' }, 400, origin);
        }

        // 更新尝试次数
        await env.DB.prepare('UPDATE verify_codes SET attempts = ? WHERE phone = ?').bind(newAttempts, phone).run();

        if (record.code !== code) {
          return jsonResponse({ error: '验证码错误' }, 400, origin);
        }

        // 验证成功，删除验证码
        await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();

        // 查找或创建用户
        let user = await env.DB.prepare('SELECT id, phone, nickname, mira_type, avatar, guest_id FROM users WHERE phone = ?').bind(phone).first();
        if (!user) {
          // 新用户：自动注册
          await env.DB.prepare('INSERT INTO users (phone, created_at, last_login_at) VALUES (?, datetime("now"), datetime("now"))').bind(phone).run();
          user = await env.DB.prepare('SELECT id, phone, nickname, mira_type, avatar, guest_id FROM users WHERE phone = ?').bind(phone).first();
        } else {
          // 更新最后登录时间
          await env.DB.prepare('UPDATE users SET last_login_at = datetime("now") WHERE id = ?').bind(user.id).run();
        }

        // 生成 JWT
        const token = await createJWT(env, { uid: user.id, gid: user.guest_id || null, phone: user.phone });

        return jsonResponse({
          success: true,
          token,
          isNewUser: !user.nickname, // 新注册用户无昵称
          user: { id: user.id, phone: user.phone, nickname: user.nickname, miraType: user.mira_type, avatar: user.avatar || '', isGuest: false }
        }, 200, origin);
      }

      // 绑定手机号（POST /api/auth/bind-phone）
      if (path === '/api/auth/bind-phone' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'bind_phone', 5, 60000)) {
          return jsonResponse({ error: '操作过于频繁' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { phone, code, token: currentToken } = body;
        if (!phone || !code) {
          return jsonResponse({ error: '手机号和验证码不能为空' }, 400, origin);
        }
        if (!/^1[3-9]\d{9}$/.test(phone)) {
          return jsonResponse({ error: '手机号格式不正确' }, 400, origin);
        }

        // 验证当前Token
        let payload;
        try {
          payload = await verifyJWT(env, currentToken);
        } catch (e) {
          return jsonResponse({ error: '登录已过期，请重新登录' }, 401, origin);
        }

        // 查验证码
        const record = await env.DB.prepare('SELECT * FROM verify_codes WHERE phone = ?').bind(phone).first();
        if (!record) {
          return jsonResponse({ error: '请先获取验证码' }, 400, origin);
        }

        if (Date.now() > record.expire_at) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();
          return jsonResponse({ error: '验证码已过期，请重新获取' }, 400, origin);
        }

        // 错误次数检查
        const newAttempts = (record.attempts || 0) + 1;
        if (newAttempts > 5) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();
          return jsonResponse({ error: '尝试次数过多，请重新获取验证码' }, 400, origin);
        }

        // 更新尝试次数
        await env.DB.prepare('UPDATE verify_codes SET attempts = ? WHERE phone = ?').bind(newAttempts, phone).run();

        if (record.code !== code) {
          return jsonResponse({ error: '验证码错误' }, 400, origin);
        }

        // 验证成功，绑定手机号
        // 先检查该手机号是否已绑定其他账号
        const existingUser = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, avatar FROM users WHERE phone = ?').bind(phone).first();
        if (existingUser && existingUser.id !== payload.uid) {
          // 手机号已绑定其他账号 → 直接登录到该账号（而非绑定到当前游客）
          await env.DB.prepare('UPDATE users SET last_login_at = datetime("now") WHERE id = ?').bind(existingUser.id).run();
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();
          const newToken = await createJWT(env, { uid: existingUser.id, gid: existingUser.guest_id, phone });
          return jsonResponse({
            success: true,
            token: newToken,
            isGuest: false,
            user: { id: existingUser.id, phone: existingUser.phone, nickname: existingUser.nickname, miraType: existingUser.mira_type, avatar: existingUser.avatar || '', isGuest: false }
          }, 200, origin);
        }

        // 手机号未被绑定，执行绑定
        try {
          await env.DB.prepare('UPDATE users SET phone = ?, last_login_at = datetime("now") WHERE id = ?').bind(phone, payload.uid).run();
        } catch (dbErr) {
          console.error('bind-phone UPDATE error:', dbErr.message);
          return jsonResponse({ error: '绑定失败，该手机号可能已被使用' }, 400, origin);
        }
        await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(phone).run();

        // 生成新Token（包含phone）
        const newToken = await createJWT(env, { uid: payload.uid, gid: payload.gid, phone });
        return jsonResponse({ success: true, token: newToken, isGuest: false }, 200, origin);
      }

      // 获取当前用户信息（GET /api/auth/me）
      if (path === '/api/auth/me' && request.method === 'GET') {
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        if (!token) {
          return jsonResponse({ error: '未登录' }, 401, origin);
        }
        try {
          const payload = await verifyJWT(env, token);
          const user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, avatar, created_at FROM users WHERE id = ?').bind(payload.uid).first();
          if (!user) {
            return jsonResponse({ error: '用户不存在' }, 404, origin);
          }
          return jsonResponse({ success: true, user: { id: user.id, phone: user.phone, nickname: user.nickname, miraType: user.mira_type, avatar: user.avatar || '', isGuest: !user.phone } }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: 'Token已过期' }, 401, origin);
        }
      }

      // ══════════════════════════════════════════ 房间管理 API ══════════════════════════════════════════

      // 创建房间（速率限制：每 IP 每分钟 5 次）
      if (path === '/api/room' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'create_room', 5, 60000)) {
          return jsonResponse({ error: '创建房间过于频繁，请稍后再试' }, 429, origin);
        }

        const code = generateRoomCode();
        const existing = await env.DB.prepare('SELECT id FROM rooms WHERE id = ?').bind(code).first();
        if (existing) {
          return jsonResponse({ error: '房间码冲突，请重试' }, 500, origin);
        }

        await env.DB.prepare(
          'INSERT INTO rooms (id, status, created_at, expires_at) VALUES (?, ?, datetime("now"), datetime("now", "+24 hours"))'
        ).bind(code, 'waiting').run();
        return jsonResponse({ code, status: 'waiting' }, 200, origin);
      }

      // 加入房间
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/join$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);
        if (room.status !== 'waiting') return jsonResponse({ error: '房间已满或已开始' }, 400, origin);

        await env.DB.prepare('UPDATE rooms SET status = ? WHERE id = ?').bind('ready', code).run();
        return jsonResponse({ code, status: 'ready' }, 200, origin);
      }

      // 获取房间状态
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT id, status, a_consent, b_consent, created_at, expires_at FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);

        if (isExpired(room)) {
          return jsonResponse({ error: '房间已过期', expired: true }, 410, origin);
        }

        return jsonResponse({
          id: room.id,
          status: room.status,
          a_consent: !!room.a_consent,
          b_consent: !!room.b_consent,
          created_at: room.created_at,
        }, 200, origin);
      }

      // 提交输入（A 或 B）— AES-GCM 加密存储
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/input$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { role, text } = body;
        const validatedRole = validateRole(role);
        if (!validatedRole) return jsonResponse({ error: '角色错误，必须为 a 或 b' }, 400, origin);
        if (!text || typeof text !== 'string') return jsonResponse({ error: '输入内容不能为空' }, 400, origin);
        if (text.length > 10000) return jsonResponse({ error: '输入内容过长（最多10000字）' }, 400, origin);

        const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);

        const otherInputField = validatedRole === 'a' ? 'b_input' : 'a_input';
        const otherRole = validatedRole === 'a' ? 'b' : 'a';

        if (room.status !== 'ready' && room.status !== `${otherRole}_input`) {
          return jsonResponse({ error: '当前状态不允许提交输入' }, 400, origin);
        }

        const myInputField = validatedRole === 'a' ? 'a_input' : 'b_input';
        if (room[myInputField]) {
          return jsonResponse({ error: '你已经提交过输入了' }, 400, origin);
        }

        // AES-GCM 加密存储（替代明文 Base64）
        const encrypted = await encryptText(env, text);
        if (!encrypted) {
          return jsonResponse({ error: '数据加密失败，请重试' }, 500, origin);
        }

        const newStatus = room[otherInputField] ? 'analyzing' : `${validatedRole}_input`;
        await env.DB.prepare(
          `UPDATE rooms SET ${myInputField} = ?, status = ? WHERE id = ?`
        ).bind(encrypted, newStatus, code).run();

        if (newStatus === 'analyzing') {
          ctx.waitUntil(analyzeCouple(env, code));
        }

        return jsonResponse({ success: true, status: newStatus }, 200, origin);
      }

      // 获取洞察摘要（严格数据隔离）
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/insight$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const roleParam = url.searchParams.get('role');
        const validatedRole = validateRole(roleParam);
        if (!validatedRole) return jsonResponse({ error: 'role 参数必须为 a 或 b' }, 400, origin);

        const room = await env.DB.prepare('SELECT a_insight, b_insight, status FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);

        if (room.status !== 'analyzed' && room.status !== 'completed') {
          return jsonResponse({ insight: null, status: room.status }, 200, origin);
        }

        // 严格隔离：a 只能看 b 的洞察，b 只能看 a 的洞察
        const insight = validatedRole === 'a' ? room.b_insight : room.a_insight;
        return jsonResponse({ insight: insight || null, status: room.status }, 200, origin);
      }

      // 同意生成共同报告（严格 role 校验）
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/consent$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const validatedRole = validateRole(body.role);
        if (!validatedRole) return jsonResponse({ error: 'role 参数必须为 a 或 b' }, 400, origin);

        const room = await env.DB.prepare('SELECT a_consent, b_consent, status FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);
        if (room.status !== 'analyzed') return jsonResponse({ error: '分析尚未完成，无法同意' }, 400, origin);

        const consentField = validatedRole === 'a' ? 'a_consent' : 'b_consent';
        if (room[consentField]) {
          return jsonResponse({ success: true, bothConsented: !!room.a_consent && !!room.b_consent, message: '你已经同意过了' }, 200, origin);
        }

        await env.DB.prepare(`UPDATE rooms SET ${consentField} = 1 WHERE id = ?`).bind(code).run();

        const updated = await env.DB.prepare('SELECT a_consent, b_consent FROM rooms WHERE id = ?').bind(code).first();
        const bothConsented = !!updated.a_consent && !!updated.b_consent;

        if (bothConsented) {
          ctx.waitUntil(generateSharedReport(env, code));
        }

        return jsonResponse({ success: true, bothConsented }, 200, origin);
      }

      // 获取共同报告
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/report$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT shared_report, status, a_consent, b_consent FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (!room.a_consent || !room.b_consent) return jsonResponse({ error: '双方未同意' }, 403, origin);
        if (room.status !== 'completed') return jsonResponse({ error: '报告尚未生成', status: room.status }, 200, origin);

        return jsonResponse({ report: room.shared_report, status: room.status }, 200, origin);
      }

      // ══════════════════════════════════════════ AI 代理 API ══════════════════════════════════════════

      // 咨询师对话（速率限制：每 IP 每分钟 15 次）
      if (path === '/api/chat' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'chat', 15, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt, history } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 10000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        const result = await callAI(env, prompt, 'chat', history || []);
        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // 单人模式 AI 分析（速率限制：每 IP 每分钟 10 次）
      if (path === '/api/analyze' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'analyze', 10, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt, mode, history } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 10000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        // 尝试从请求头拿 uid（无 token 则 uid=null，兼容游客）
        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        const result = await callAI(env, prompt, mode || 'single', history || []);

        if (!result.error && (mode || 'single') === 'single') {
          ctx.waitUntil(saveSingleAnalysis(env, prompt, result, uid));
        }

        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // 写信模式
      if (path === '/api/letter' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'letter', 10, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt, history } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);

        const result = await callAI(env, prompt, 'letter', history || []);
        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // MIRA 人格测试判题
      if (path === '/api/mira-quiz' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'mira_quiz', 5, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt, scores, answers, miraType: clientMiraType } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 15000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        // 尝试从请求头拿 uid
        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        const result = await callAI(env, prompt, 'quiz', []);

        // 确定最终 miraType：优先用 AI 返回的，否则用前端计分系统确定的
        const finalMiraType = (result && !result.error && result.miraType) ? result.miraType : (clientMiraType || '');

        // 有 uid 且有 miraType 就保存（即使 AI 失败也保存基础数据）
        if (uid && finalMiraType) {
          ctx.waitUntil((async () => {
            try {
              let scoresJson = '{}';
              let answersJson = '{}';
              try { scoresJson = JSON.stringify(scores || {}); } catch (e) { scoresJson = '{}'; }
              try { answersJson = JSON.stringify(answers || {}); } catch (e) { answersJson = '{}'; }

              await env.DB.prepare(
                'INSERT INTO mira_tests (user_id, mira_type, expression, focus, portrait, scores_json, answers_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, datetime("now"))'
              ).bind(
                uid,
                finalMiraType,
                (result && result.expression) || '',
                (result && result.focus) || '',
                (result && result.portrait) || '',
                scoresJson,
                answersJson,
              ).run();

              // 同时更新 users.mira_type
              await env.DB.prepare('UPDATE users SET mira_type = ? WHERE id = ?').bind(finalMiraType, uid).run();
            } catch (err) {
              console.error('saveMiraTest error:', err.message);
            }
          })());
        }

        // 即使 AI 失败，也确保返回 miraType 给前端
        if (result.error && clientMiraType) {
          return jsonResponse({ miraType: clientMiraType, expression: '', focus: '', portrait: '', insight: '', suggest: '' }, 200, origin);
        }
        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // MIRA 深度解读
      if (path === '/api/mira-deep' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'mira_deep', 5, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 15000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        const result = await callAI(env, prompt, 'deep', []);
        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // ══════════════════════════════════════════ 阶段二：分享卡片金句生成 ══════════════════════════════════════════

      // 生成个性化金句（用于分享卡片）
      if (path === '/api/quote' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'quote', 10, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后重试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { miraType, insight, emotion, need } = body;
        if (!miraType || typeof miraType !== 'string') return jsonResponse({ error: 'miraType 不能为空' }, 400, origin);

        const quotePrompt = `基于以下用户信息，生成一句有共鸣、值得分享的金句（20-40字，像朋友说的心里话，不要鸡汤，不要说教，可以带一点自嘲或反差）：

MIRA类型：${miraType}
洞察：${insight || ''}
情绪：${emotion || ''}
需求：${need || ''}

要求：
1. 像朋友说的心里话，不是格言不是鸡汤
2. 带一点自嘲或反差更好（如"嘴上说无所谓，半夜会反复看消息"）
3. 让人看到就想转发，因为"说的就是我"
4. 只输出金句本身，不要引号不要解释

示例：
- 你是那种嘴上说无所谓，半夜会反复看消息的人
- 你总说"我没事"，但你心里的事比谁都多
- 你不是不在乎，你只是把在乎藏得太深了`;

        const result = await callAI(env, quotePrompt, 'quote', []);
        if (result.error) {
          // AI 失败时返回基于类型的兜底金句
          const fallbackQuotes = {
            'DO': '你几乎不说出自己的感受，但你的沉默比谁都深情',
            'DT': '你不善言辞，但你总是在场，这本身就是最深的话',
            'DI': '你习惯把一切藏在心里，但心里装的不止是你的事',
            'DN': '你像深海一样安静，但深处的暗涌只有你自己知道',
            'SO': '你总是温柔地听别人说，但谁在听你说？',
            'ST': '你像镜子一样照见别人，也别忘了照照自己',
            'SI': '你善于反思，但有些答案不在脑子里，在感受里',
            'SN': '你的沉默不是空的，里面装满了一个人的宇宙',
            'BO': '你总把别人放在第一位，但谁在守护你？',
            'BT': '你相信坦诚比和谐重要，这很勇敢',
            'BI': '你知道自己的底线，这是对关系最真诚的尊重',
            'BN': '你清楚自己要什么，但偶尔也留点空间给沉默',
            'RO': '你毫无保留地付出，但热烈也需要被接住',
            'RT': '你一眼看穿问题，但有时候真相需要包一层温柔',
            'RI': '你不会为关系改变自己，因为好的关系不需要你变形',
            'RN': '你和自己在对话，而你是自己最好的听众',
          };
          return jsonResponse({ quote: fallbackQuotes[miraType] || '你值得被看见，不是因为你完美，而是因为你真实' }, 200, origin);
        }

        const quoteText = (result.raw || result.reply || '').trim().replace(/^["'""]|["'""]$/g, '');
        return jsonResponse({ quote: quoteText || '你值得被看见，不是因为你完美，而是因为你真实' }, 200, origin);
      }

      // ══════════════════════════════════════════ 阶段三：双人模式房间状态增强 ══════════════════════════════════════════

      // 房间状态增强查询（含倒计时、对方输入状态）
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/status$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT id, status, a_consent, b_consent, created_at, expires_at, a_input, b_input FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);

        // 计算剩余时间
        const now = Date.now();
        let expiresAt = room.expires_at ? new Date(room.expires_at + 'Z').getTime() : (now + 24 * 60 * 60 * 1000);
        let remainingMs = Math.max(0, expiresAt - now);
        let remainingHours = Math.floor(remainingMs / (60 * 60 * 1000));
        let remainingMinutes = Math.floor((remainingMs % (60 * 60 * 1000)) / (60 * 1000));
        let isExpiringSoon = remainingMs < 60 * 60 * 1000; // 1小时内过期

        return jsonResponse({
          status: room.status,
          aConsent: !!room.a_consent,
          bConsent: !!room.b_consent,
          aSubmitted: !!room.a_input,
          bSubmitted: !!room.b_input,
          remainingMs,
          remainingHours,
          remainingMinutes,
          isExpiringSoon,
          createdAt: room.created_at,
          expiresAt: room.expires_at,
        }, 200, origin);
      }

      // ══════════════════════════════════════════ 阶段四：动态画像 & 历史记录 & 洞察日记 ══════════════════════════════════════════

      // 获取分析历史趋势（用于动态画像雷达图）
      if (path === '/api/user/trends' && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        try {
          const records = await env.DB.prepare(
            'SELECT mira_type, dimensions_json, insight_summary, emotion_snapshot, need_snapshot, created_at FROM analysis_history WHERE user_id = ? ORDER BY created_at ASC'
          ).bind(auth.uid).all();

          const list = records.results || [];

          // 如果有多条记录，计算维度变化趋势
          let trendData = [];
          list.forEach(function(r) {
            let dims = {};
            try { dims = JSON.parse(r.dimensions_json || '{}'); } catch(e) {}
            trendData.push({
              miraType: r.mira_type,
              dimensions: dims,
              insight: r.insight_summary,
              emotion: r.emotion_snapshot,
              need: r.need_snapshot,
              date: r.created_at,
            });
          });

          return jsonResponse({
            total: list.length,
            trends: trendData,
            hasEnoughData: list.length >= 2,
          }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '获取趋势数据失败' }, 500, origin);
        }
      }

      // 获取洞察日记列表
      if (path === '/api/user/diaries' && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        try {
          const records = await env.DB.prepare(
            'SELECT id, source_type, diary_text, emotion_tag, growth_tag, created_at FROM insight_diaries WHERE user_id = ? ORDER BY created_at DESC LIMIT 50'
          ).bind(auth.uid).all();

          return jsonResponse({
            list: records.results || [],
            total: (records.results || []).length,
          }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '获取日记失败' }, 500, origin);
        }
      }

      // ══════════════════════════════════════════ 阶段五：决策树管理 API ══════════════════════════════════════════

      // 获取决策树所有节点（后台管理用）
      if (path === '/api/admin/decision-tree' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        try {
          const records = await env.DB.prepare(
            'SELECT * FROM chat_decision_tree ORDER BY sort_order ASC'
          ).all();
          return jsonResponse({ nodes: records.results || [] }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '获取决策树失败' }, 500, origin);
        }
      }

      // 更新决策树节点（后台管理用）
      if (path === '/api/admin/decision-tree' && request.method === 'PUT') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { id, node_id, parent_id, node_type, condition_type, condition_value, prompt_template, next_node_sufficient, next_node_insufficient, description, is_active, sort_order } = body;

        if (!node_id || !node_type || !prompt_template) {
          return jsonResponse({ error: '缺少必填字段' }, 400, origin);
        }

        try {
          if (id) {
            await env.DB.prepare(
              'UPDATE chat_decision_tree SET node_id=?, parent_id=?, node_type=?, condition_type=?, condition_value=?, prompt_template=?, next_node_sufficient=?, next_node_insufficient=?, description=?, is_active=?, sort_order=?, updated_at=datetime("now") WHERE id=?'
            ).bind(node_id, parent_id || null, node_type, condition_type || '', condition_value || '', prompt_template, next_node_sufficient || null, next_node_insufficient || null, description || '', is_active !== undefined ? (is_active ? 1 : 0) : 1, sort_order || 0, id).run();
          } else {
            await env.DB.prepare(
              'INSERT INTO chat_decision_tree (node_id, parent_id, node_type, condition_type, condition_value, prompt_template, next_node_sufficient, next_node_insufficient, description, is_active, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
            ).bind(node_id, parent_id || null, node_type, condition_type || '', condition_value || '', prompt_template, next_node_sufficient || null, next_node_insufficient || null, description || '', is_active !== undefined ? (is_active ? 1 : 0) : 1, sort_order || 0).run();
          }
          return jsonResponse({ success: true }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '保存失败: ' + e.message }, 500, origin);
        }
      }

      // 删除决策树节点
      if (path === '/api/admin/decision-tree' && request.method === 'DELETE') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { id } = body;
        if (!id) return jsonResponse({ error: '缺少节点ID' }, 400, origin);

        try {
          await env.DB.prepare('DELETE FROM chat_decision_tree WHERE id = ?').bind(id).run();
          return jsonResponse({ success: true }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '删除失败' }, 500, origin);
        }
      }

      // ══════════════════════════════════════════ 阶段五：决策树驱动的咨询师对话 ══════════════════════════════════════════

      // 咨询师对话（决策树增强版，向后兼容旧逻辑）
      if (path === '/api/chat-v2' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'chat', 15, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后重试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt, history, currentNodeId, sufficientSignals, round } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 10000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        // 获取决策树节点
        let treeNodes = [];
        try {
          const treeResult = await env.DB.prepare('SELECT * FROM chat_decision_tree WHERE is_active = 1 ORDER BY sort_order ASC').all();
          treeNodes = treeResult.results || [];
        } catch (e) {
          // 决策树表不存在，回退到旧逻辑
        }

        // 如果有决策树数据，使用决策树驱动
        if (treeNodes.length > 0 && currentNodeId) {
          const currentNode = treeNodes.find(function(n) { return n.node_id === currentNodeId; });
          if (currentNode) {
            // 根据条件判断下一步
            const signals = sufficientSignals || { hasFact: false, hasEmotion: false, hasNeed: false };
            const currentRound = round || 1;

            let nextNodeId = null;
            if (currentNode.condition_type === 'has_fact') {
              nextNodeId = signals.hasFact ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
            } else if (currentNode.condition_type === 'has_emotion') {
              nextNodeId = signals.hasEmotion ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
            } else if (currentNode.condition_type === 'has_need') {
              nextNodeId = signals.hasNeed ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
            } else if (currentNode.condition_type === 'round_count') {
              nextNodeId = currentRound >= parseInt(currentNode.condition_value) ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
            } else {
              nextNodeId = currentNode.next_node_sufficient;
            }

            // 构建基于决策树的 system prompt 并传递给 AI
            const nodePrompt = currentNode.prompt_template
              .replace(/\{userInput\}/g, prompt.substring(0, 500))
              .replace(/\{round\}/g, currentRound)
              .replace(/\{emotion\}/g, signals.emotion || '');

            const result = await callAI(env, prompt, 'chat', history || [], nodePrompt);
            return jsonResponse({
              ...result,
              currentNodeId: nextNodeId,
              nodeType: currentNode.node_type,
            }, result.error ? 500 : 200, origin);
          }
        }

        // 回退到旧逻辑
        const result = await callAI(env, prompt, 'chat', history || []);
        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // ══════════════════════════════════════════ 数据库初始化 API ══════════════════════════════════════════

      // 初始化数据库表（GET /api/init-db）
      if (path === '/api/init-db' && request.method === 'GET') {
        try {
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS single_analyses (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_input TEXT NOT NULL,
              fact TEXT DEFAULT '',
              emotion TEXT DEFAULT '',
              need TEXT DEFAULT '',
              misread TEXT DEFAULT '',
              status TEXT DEFAULT '',
              insight TEXT DEFAULT '',
              suggest TEXT DEFAULT '',
              mira_type TEXT DEFAULT '',
              created_at TEXT DEFAULT (datetime('now'))
            )
          `).run();

          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS mira_tests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              mira_type TEXT NOT NULL,
              expression TEXT DEFAULT '',
              focus TEXT DEFAULT '',
              portrait TEXT DEFAULT '',
              scores_json TEXT DEFAULT '{}',
              answers_json TEXT DEFAULT '{}',
              created_at TEXT DEFAULT (datetime('now'))
            )
          `).run();

          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS user_contacts (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER,
              contact_type TEXT NOT NULL,
              contact_value TEXT NOT NULL,
              source TEXT DEFAULT '',
              mira_type TEXT DEFAULT '',
              created_at TEXT DEFAULT (datetime('now'))
            )
          `).run();
          try { await env.DB.prepare("ALTER TABLE user_contacts ADD COLUMN user_id INTEGER").run(); } catch(e) { /* 已存在 */ }

          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              guest_id TEXT UNIQUE,
              phone TEXT UNIQUE,
              password_hash TEXT,
              password_salt TEXT,
              nickname TEXT,
              mira_type TEXT,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              last_login_at DATETIME
            )
          `).run();

          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS verify_codes (
              phone TEXT PRIMARY KEY,
              code TEXT NOT NULL,
              expire_at INTEGER NOT NULL,
              attempts INTEGER DEFAULT 0,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();

          // 短信发送日志表（持久化限流，防多实例绕过）
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS sms_send_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              phone TEXT NOT NULL,
              ip TEXT NOT NULL,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              created_at_ms INTEGER NOT NULL
            )
          `).run();

          // 创建索引优化查询
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_rooms_status ON rooms(status)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_rooms_expires ON rooms(expires_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_users_guest ON users(guest_id)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_sms_log_phone_time ON sms_send_log(phone, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_sms_log_ip_time ON sms_send_log(ip, created_at_ms)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_sms_log_ip_date ON sms_send_log(ip, created_at)').run();

          // API 速率限制日志表（D1持久化，防多实例绕过，用于AI端点和认证端点）
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS api_rate_limits (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              ip TEXT NOT NULL,
              endpoint TEXT NOT NULL,
              created_at_ms INTEGER NOT NULL
            )
          `).run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_api_rl_ip_endpoint_time ON api_rate_limits(ip, endpoint, created_at_ms)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_api_rl_cleanup ON api_rate_limits(created_at_ms)').run();

          // ═══ 后台管理相关表 ═══

          // 管理员配置表（IP白名单等动态配置）
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS admin_config (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              config_key TEXT UNIQUE NOT NULL,
              config_value TEXT NOT NULL,
              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();

          // 安全日志表
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS security_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              event_type TEXT NOT NULL,
              event_detail TEXT,
              ip TEXT NOT NULL,
              endpoint TEXT,
              user_id INTEGER,
              admin_id TEXT,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();

          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_security_logs_type ON security_logs(event_type, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_security_logs_ip ON security_logs(ip, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_security_logs_created ON security_logs(created_at)').run();

          // 为 users 表添加状态字段（如果还没有）
          try { await env.DB.prepare("ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'normal'").run(); } catch(e) { /* 已存在 */ }

          // ═══ 个人中心相关表 ═══

          // 双人房间记录副本表（永久保存）
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS user_room_records (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              room_code TEXT NOT NULL,
              role TEXT NOT NULL,
              partner_mira_type TEXT,
              my_mira_type TEXT,
              shared_report_json TEXT,
              my_insight_json TEXT,
              partner_insight_json TEXT,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              source_room_expires_at DATETIME
            )
          `).run();

          // 为 single_analyses 增加 user_id + report_json
          try { await env.DB.prepare('ALTER TABLE single_analyses ADD COLUMN user_id INTEGER').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare("ALTER TABLE single_analyses ADD COLUMN report_json TEXT DEFAULT '{}'").run(); } catch(e) { /* 已存在 */ }

          // 为 mira_tests 增加 user_id + deep_text
          try { await env.DB.prepare('ALTER TABLE mira_tests ADD COLUMN user_id INTEGER').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare("ALTER TABLE mira_tests ADD COLUMN deep_text TEXT DEFAULT ''").run(); } catch(e) { /* 已存在 */ }

          // 为 rooms 增加 a_uid + b_uid
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN a_uid INTEGER').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN b_uid INTEGER').run(); } catch(e) { /* 已存在 */ }

          // 为报告表增加查看/分享次数统计字段
          try { await env.DB.prepare('ALTER TABLE single_analyses ADD COLUMN view_count INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE single_analyses ADD COLUMN share_count INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE mira_tests ADD COLUMN view_count INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE mira_tests ADD COLUMN share_count INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE user_room_records ADD COLUMN view_count INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE user_room_records ADD COLUMN share_count INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }

          // 个人中心索引
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_single_analyses_user ON single_analyses(user_id, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_mira_tests_user ON mira_tests(user_id, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_user_room_records_user ON user_room_records(user_id, created_at)').run();

          // 为老 users 表添加密码字段（如果不存在）
          try { await env.DB.prepare('ALTER TABLE users ADD COLUMN password_hash TEXT').run(); } catch(e) { /* 字段已存在 */ }
          try { await env.DB.prepare('ALTER TABLE users ADD COLUMN password_salt TEXT').run(); } catch(e) { /* 字段已存在 */ }
          // 为 users 表添加 avatar 字段（预设头像标识）
          try { await env.DB.prepare('ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ""').run(); } catch(e) { /* 字段已存在 */ }

          // ═══ 阶段四：数据粘性 — 分析历史 & 洞察日记 ═══
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS analysis_history (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              source_type TEXT NOT NULL,
              source_id INTEGER,
              mira_type TEXT,
              dimensions_json TEXT DEFAULT '{}',
              insight_summary TEXT DEFAULT '',
              emotion_snapshot TEXT DEFAULT '',
              need_snapshot TEXT DEFAULT '',
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_analysis_history_user ON analysis_history(user_id, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_analysis_history_type ON analysis_history(user_id, source_type, created_at)').run();

          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS insight_diaries (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER NOT NULL,
              source_type TEXT NOT NULL,
              source_id INTEGER,
              diary_text TEXT NOT NULL,
              emotion_tag TEXT DEFAULT '',
              growth_tag TEXT DEFAULT '',
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_insight_diaries_user ON insight_diaries(user_id, created_at)').run();

          // ═══ 阶段五：咨询师模式决策树 ═══
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS chat_decision_tree (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              node_id TEXT UNIQUE NOT NULL,
              parent_id TEXT,
              node_type TEXT NOT NULL,
              condition_type TEXT DEFAULT '',
              condition_value TEXT DEFAULT '',
              prompt_template TEXT NOT NULL,
              next_node_sufficient TEXT,
              next_node_insufficient TEXT,
              description TEXT DEFAULT '',
              is_active INTEGER DEFAULT 1,
              sort_order INTEGER DEFAULT 0,
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_chat_tree_parent ON chat_decision_tree(parent_id)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_chat_tree_active ON chat_decision_tree(is_active, sort_order)').run();

          // 决策树种子数据（仅首次插入）
          const treeCount = await env.DB.prepare('SELECT COUNT(*) as cnt FROM chat_decision_tree').first();
          if (treeCount && treeCount.cnt === 0) {
            const seedNodes = [
              ['start', null, 'collect', '', '', '你是 Mirror，一位关系咨询师。用户刚开口说了：{userInput}。请用1句话承接情绪，然后基于依恋理论判断追问方向。', 'assess_fact', null, '起始节点：承接情绪+判断方向', 1, 0],
              ['assess_fact', 'start', 'ask', 'has_fact', 'true', '用户已提供具体事实。检查是否需要追问情绪。', 'assess_emotion', 'ask_fact', '评估事实维度是否充足', 1, 1],
              ['ask_fact', 'assess_fact', 'ask', 'has_fact', 'false', '用户缺少具体事实。问：能给我举个例子吗？或：具体是哪一次？', 'assess_emotion', null, '追问事实', 1, 2],
              ['assess_emotion', 'assess_fact', 'ask', 'has_emotion', 'true', '用户已表达情绪。检查是否需要追问需求。', 'assess_need', 'ask_emotion', '评估情绪维度是否充足', 1, 3],
              ['ask_emotion', 'assess_emotion', 'ask', 'has_emotion', 'false', '用户缺少情绪表达。问：那时候你心里是什么感觉？', 'assess_need', null, '追问情绪', 1, 4],
              ['assess_need', 'assess_emotion', 'ask', 'has_need', 'true', '三个维度都充足。给用户选择权。', 'offer_analyze', 'ask_need', '评估需求维度是否充足', 1, 5],
              ['ask_need', 'assess_need', 'ask', 'has_need', 'false', '用户缺少需求表达。问：你真正想要的是什么？', 'offer_analyze', null, '追问需求', 1, 6],
              ['offer_analyze', 'assess_need', 'offer_analyze', '', '', '聊了这么多，信息看起来够了。我来帮你梳理一下？还是你想再聊聊？', 'analyze', 'continue_chat', '信息充足，给用户选择', 1, 7],
              ['continue_chat', 'offer_analyze', 'ask', 'round_count', '>=50', '已达50轮软上限，自动切换到分析。', 'analyze', 'continue_chat', '继续对话（50轮后强制分析）', 1, 8],
              ['analyze', 'offer_analyze', 'analyze', '', '', '聊了这么多，我来帮你梳理一下。', 'end', null, '生成分析报告', 1, 9],
              ['end', 'analyze', 'end', '', '', '分析已完成。', null, null, '结束节点', 1, 10],
            ];
            for (const node of seedNodes) {
              await env.DB.prepare(
                'INSERT OR IGNORE INTO chat_decision_tree (node_id, parent_id, node_type, condition_type, condition_value, prompt_template, next_node_sufficient, next_node_insufficient, description, is_active, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
              ).bind(...node).run();
            }
          }

          // 兼容旧数据：将 continue_chat 节点的轮次上限从 >=5 更新为 >=50
          try { await env.DB.prepare("UPDATE chat_decision_tree SET condition_value = '>=50', prompt_template = '已达50轮软上限，自动切换到分析。' WHERE node_id = 'continue_chat' AND condition_value = '>=5'").run(); } catch(e) {}

          // schema_version 版本管理表
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS schema_version (
              version INTEGER PRIMARY KEY,
              description TEXT,
              applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          // 记录当前版本
          try {
            await env.DB.prepare('INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)').bind(2, 'v2: analysis_history, insight_diaries, chat_decision_tree').run();
          } catch(e) { /* 已存在 */ }

          return jsonResponse({ success: true, message: '数据库表创建/验证完成' }, 200, origin);
        } catch (err) {
          console.error('init-db error:', err.message);
          return jsonResponse({ error: '数据库初始化失败' }, 500, origin);
        }
      }

      // ══════════════════════════════════════════ 个人中心 API（阶段B：账号管理） ══════════════════════════════════════════

      // 修改昵称（PUT /api/user/nickname）
      if (path === '/api/user/nickname' && request.method === 'PUT') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { nickname } = body;
        if (!nickname || typeof nickname !== 'string' || nickname.trim().length === 0 || nickname.length > 20) {
          return jsonResponse({ error: '昵称长度需为1-20个字符' }, 400, origin);
        }

        await env.DB.prepare('UPDATE users SET nickname = ? WHERE id = ?').bind(nickname.trim(), auth.uid).run();
        return jsonResponse({ success: true, user: { nickname: nickname.trim() } }, 200, origin);
      }

      // 修改头像（PUT /api/user/avatar）
      if (path === '/api/user/avatar' && request.method === 'PUT') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { avatar } = body;
        // avatar 是预设头像标识符，如 "aurora"、"ember" 等，限制长度防止滥用
        if (!avatar || typeof avatar !== 'string' || avatar.length < 1 || avatar.length > 30) {
          return jsonResponse({ error: '头像标识无效' }, 400, origin);
        }
        // 仅允许字母数字下划线
        if (!/^[a-zA-Z0-9_]+$/.test(avatar)) {
          return jsonResponse({ error: '头像标识格式错误' }, 400, origin);
        }

        await env.DB.prepare('UPDATE users SET avatar = ? WHERE id = ?').bind(avatar, auth.uid).run();
        return jsonResponse({ success: true, user: { avatar: avatar } }, 200, origin);
      }

      // 修改密码（PUT /api/user/password）
      if (path === '/api/user/password' && request.method === 'PUT') {
        if (!await checkRateLimitD1(env, clientIP, 'change_password', 5, 60000)) {
          return jsonResponse({ error: '操作过于频繁，请稍后再试' }, 429, origin);
        }

        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { oldPassword, newPassword } = body;
        if (!newPassword || typeof newPassword !== 'string' || newPassword.length < 4 || newPassword.length > 32) {
          return jsonResponse({ error: '新密码长度需为4-32个字符' }, 400, origin);
        }
        if (!oldPassword || typeof oldPassword !== 'string') {
          return jsonResponse({ error: '请输入旧密码' }, 400, origin);
        }

        // 查询用户密码
        const userRow = await env.DB.prepare('SELECT password_hash, password_salt FROM users WHERE id = ?').bind(auth.uid).first();
        if (!userRow) return jsonResponse({ error: '用户不存在' }, 404, origin);

        // 若无密码（手机号登录用户从未设过密码），先用默认密码1234初始化
        let storedHash = userRow.password_hash;
        let storedSalt = userRow.password_salt;
        if (!storedHash || !storedSalt) {
          const initResult = await initUserPassword(env, auth.uid);
          storedHash = initResult.hash;
          storedSalt = initResult.salt;
        }

        // 校验旧密码
        const oldHash = await hashPassword(oldPassword, storedSalt);
        if (oldHash !== storedHash) {
          return jsonResponse({ error: '旧密码错误' }, 400, origin);
        }

        // 生成新salt + hash 并更新
        const newSalt = generateSalt();
        const newHash = await hashPassword(newPassword, newSalt);
        await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(newHash, newSalt, auth.uid).run();

        return jsonResponse({ success: true }, 200, origin);
      }

      // 更换手机号 - 发送验证码（POST /api/user/phone/send-code）
      if (path === '/api/user/phone/send-code' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'phone_send_code', 5, 60000)) {
          return jsonResponse({ error: '操作过于频繁，请稍后再试' }, 429, origin);
        }

        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { newPhone, turnstileToken } = body;
        if (!newPhone || !/^1[3-9]\d{9}$/.test(newPhone)) {
          return jsonResponse({ error: '手机号格式不正确' }, 400, origin);
        }

        // 不能与当前手机号相同
        if (auth.user.phone && auth.user.phone === newPhone) {
          return jsonResponse({ error: '新手机号不能与当前手机号相同' }, 400, origin);
        }

        // Turnstile 人机验证
        const turnstileResult = await verifyTurnstile(env, turnstileToken, clientIP);
        if (!turnstileResult.success) {
          return jsonResponse({ error: turnstileResult.error, needTurnstile: true }, 400, origin);
        }

        // 检查 newPhone 是否已被其他用户占用
        const existUser = await env.DB.prepare('SELECT id FROM users WHERE phone = ? AND id != ?').bind(newPhone, auth.uid).first();
        if (existUser) {
          return jsonResponse({ error: '该手机号已被其他账号绑定' }, 400, origin);
        }

        // D1 持久化限流
        const rateResult = await checkSmsRateLimit(env, newPhone, clientIP);
        if (!rateResult.allowed) {
          return jsonResponse({ error: rateResult.reason, code: rateResult.code }, 429, origin);
        }

        // 60秒冷却（基于 verify_codes 表）
        const existing = await env.DB.prepare('SELECT created_at FROM verify_codes WHERE phone = ?').bind(newPhone).first();
        if (existing) {
          const elapsed = Date.now() - new Date(existing.created_at).getTime();
          if (elapsed < 60000) {
            return jsonResponse({ error: '请稍后再试', remainSeconds: Math.ceil((60000 - elapsed) / 1000) }, 429, origin);
          }
        }

        // 生成6位验证码
        const code = String(Math.floor(100000 + Math.random() * 900000));
        const expireAt = Date.now() + 5 * 60 * 1000;

        try {
          await env.DB.prepare(
            'INSERT OR REPLACE INTO verify_codes (phone, code, expire_at, attempts, created_at) VALUES (?, ?, ?, 0, datetime("now"))'
          ).bind(newPhone, code, expireAt).run();
        } catch (dbErr) {
          console.error('D1 Insert error:', dbErr.message, 'Phone:', newPhone);
          return jsonResponse({ error: '系统繁忙，请稍后重试' }, 500, origin);
        }

        // 调用阿里云短信API发送
        const smsResult = await sendAliyunSms(env, newPhone, { code });
        if (!smsResult.success) {
          console.error('SMS send failed:', smsResult.error, 'Phone:', newPhone);
          if (smsResult.error === '短信服务未配置') {
            console.log(`[SMS-DEV] 换号验证码: ${code}, 手机号: ${newPhone}`);
            return jsonResponse({ success: true, expireIn: 300, devCode: code }, 200, origin);
          }
          return jsonResponse({ error: '短信发送失败，请稍后重试' }, 500, origin);
        }

        try { await logSmsSend(env, newPhone, clientIP); } catch (logErr) { console.error('SMS log error:', logErr.message); }

        return jsonResponse({ success: true, expireIn: 300 }, 200, origin);
      }

      // 更换手机号 - 验证并更换（PUT /api/user/phone）
      if (path === '/api/user/phone' && request.method === 'PUT') {
        if (!await checkRateLimitD1(env, clientIP, 'phone_change', 5, 60000)) {
          return jsonResponse({ error: '操作过于频繁，请稍后再试' }, 429, origin);
        }

        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { newPhone, code } = body;
        if (!newPhone || !/^1[3-9]\d{9}$/.test(newPhone)) {
          return jsonResponse({ error: '手机号格式不正确' }, 400, origin);
        }
        if (!code || code.length !== 6) {
          return jsonResponse({ error: '请输入6位验证码' }, 400, origin);
        }

        // 查验证码
        const record = await env.DB.prepare('SELECT * FROM verify_codes WHERE phone = ?').bind(newPhone).first();
        if (!record) {
          return jsonResponse({ error: '请先获取验证码' }, 400, origin);
        }

        if (Date.now() > record.expire_at) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(newPhone).run();
          return jsonResponse({ error: '验证码已过期，请重新获取' }, 400, origin);
        }

        // 错误次数检查（5次错误失效）
        const newAttempts = (record.attempts || 0) + 1;
        if (newAttempts > 5) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(newPhone).run();
          return jsonResponse({ error: '尝试次数过多，请重新获取验证码' }, 400, origin);
        }

        await env.DB.prepare('UPDATE verify_codes SET attempts = ? WHERE phone = ?').bind(newAttempts, newPhone).run();

        if (record.code !== code) {
          return jsonResponse({ error: '验证码错误' }, 400, origin);
        }

        // 再次确认 newPhone 未被占用（防并发）
        const existUser = await env.DB.prepare('SELECT id FROM users WHERE phone = ? AND id != ?').bind(newPhone, auth.uid).first();
        if (existUser) {
          await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(newPhone).run();
          return jsonResponse({ error: '该手机号已被其他账号绑定' }, 400, origin);
        }

        // 更新手机号，删除验证码记录
        await env.DB.prepare('UPDATE users SET phone = ? WHERE id = ?').bind(newPhone, auth.uid).run();
        await env.DB.prepare('DELETE FROM verify_codes WHERE phone = ?').bind(newPhone).run();

        // 签发新JWT（含新phone）
        const newToken = await createJWT(env, { uid: auth.uid, gid: auth.user.guest_id || null, phone: newPhone });
        return jsonResponse({ success: true, token: newToken }, 200, origin);
      }

      // 退出登录（POST /api/auth/logout）
      if (path === '/api/auth/logout' && request.method === 'POST') {
        // 速率限制
        if (!checkRateLimit(clientIP, 'logout', 5, 60000)) {
          return jsonResponse({ error: '操作过于频繁，请稍后再试' }, 429, origin);
        }

        // 鉴权可选：有token则验证，无token也返回成功
        const authHeader = request.headers.get('Authorization') || '';
        const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
        if (token) {
          try { await verifyJWT(env, token); } catch (e) { /* token 无效也允许退出 */ }
        }

        // JWT 无状态，后端无需特殊处理，前端清 localStorage
        return jsonResponse({ success: true }, 200, origin);
      }

      // ══════════════════════════════════════════ 个人中心 API（阶段C：数据查询） ══════════════════════════════════════════

      // 分析记录列表（GET /api/user/analyses）
      if (path === '/api/user/analyses' && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let page = parseInt(url.searchParams.get('page') || '1', 10);
        let size = parseInt(url.searchParams.get('size') || '20', 10);
        if (!page || page < 1) page = 1;
        if (!size || size < 1) size = 20;
        if (size > 50) size = 50;
        const offset = (page - 1) * size;

        const [listRes, countRes] = await Promise.all([
          env.DB.prepare('SELECT id, status, mira_type, insight, created_at FROM single_analyses WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(auth.uid, size, offset).all(),
          env.DB.prepare('SELECT COUNT(*) as total FROM single_analyses WHERE user_id = ?').bind(auth.uid).first(),
        ]);

        return jsonResponse({ list: listRes.results || [], total: (countRes && countRes.total) || 0, page }, 200, origin);
      }

      // 单条分析完整报告（GET /api/user/analyses/:id）
      if (path.startsWith('/api/user/analyses/') && !path.endsWith('/api/user/analyses/') && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        const idStr = path.split('/').pop();
        const id = parseInt(idStr, 10);
        if (!id) return jsonResponse({ error: '无效的记录ID' }, 400, origin);

        const row = await env.DB.prepare('SELECT * FROM single_analyses WHERE id = ? AND user_id = ?').bind(id, auth.uid).first();
        if (!row) return jsonResponse({ error: '记录不存在' }, 404, origin);

        // 记录查看次数
        ctx.waitUntil(env.DB.prepare('UPDATE single_analyses SET view_count = view_count + 1 WHERE id = ?').bind(id).run());

        let reportJson = null;
        try { reportJson = row.report_json ? JSON.parse(row.report_json) : null; } catch (e) { reportJson = null; }

        return jsonResponse({
          id: row.id,
          user_input: row.user_input,
          fact: row.fact,
          emotion: row.emotion,
          need: row.need,
          misread: row.misread,
          status: row.status,
          insight: row.insight,
          suggest: row.suggest,
          mira_type: row.mira_type,
          created_at: row.created_at,
          report: reportJson,
        }, 200, origin);
      }

      // 最新 MIRA 结果（GET /api/user/mira）
      if (path === '/api/user/mira' && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        const row = await env.DB.prepare('SELECT * FROM mira_tests WHERE user_id = ? ORDER BY created_at DESC LIMIT 1').bind(auth.uid).first();
        if (!row) return jsonResponse({ mira: null }, 200, origin);

        // 记录查看次数
        ctx.waitUntil(env.DB.prepare('UPDATE mira_tests SET view_count = view_count + 1 WHERE id = ?').bind(row.id).run());

        let scoresJson = null, answersJson = null;
        try { scoresJson = row.scores_json ? JSON.parse(row.scores_json) : null; } catch (e) { scoresJson = null; }
        try { answersJson = row.answers_json ? JSON.parse(row.answers_json) : null; } catch (e) { answersJson = null; }

        return jsonResponse({
          mira: {
            id: row.id,
            mira_type: row.mira_type,
            expression: row.expression,
            focus: row.focus,
            portrait: row.portrait,
            deep_text: row.deep_text || '',
            scores: scoresJson,
            answers: answersJson,
            created_at: row.created_at,
          }
        }, 200, origin);
      }

      // 房间记录列表（GET /api/user/rooms）
      if (path === '/api/user/rooms' && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        let page = parseInt(url.searchParams.get('page') || '1', 10);
        let size = parseInt(url.searchParams.get('size') || '20', 10);
        if (!page || page < 1) page = 1;
        if (!size || size < 1) size = 20;
        if (size > 50) size = 50;
        const offset = (page - 1) * size;

        const [listRes, countRes] = await Promise.all([
          env.DB.prepare('SELECT id, room_code, role, my_mira_type, partner_mira_type, created_at FROM user_room_records WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?').bind(auth.uid, size, offset).all(),
          env.DB.prepare('SELECT COUNT(*) as total FROM user_room_records WHERE user_id = ?').bind(auth.uid).first(),
        ]);

        return jsonResponse({ list: listRes.results || [], total: (countRes && countRes.total) || 0, page }, 200, origin);
      }

      // 单条房间记录详情（GET /api/user/rooms/:id）
      if (path.startsWith('/api/user/rooms/') && !path.endsWith('/api/user/rooms/') && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        const idStr = path.split('/').pop();
        const id = parseInt(idStr, 10);
        if (!id) return jsonResponse({ error: '无效的记录ID' }, 400, origin);

        const row = await env.DB.prepare('SELECT * FROM user_room_records WHERE id = ? AND user_id = ?').bind(id, auth.uid).first();
        if (!row) return jsonResponse({ error: '记录不存在' }, 404, origin);

        // 记录查看次数
        ctx.waitUntil(env.DB.prepare('UPDATE user_room_records SET view_count = view_count + 1 WHERE id = ?').bind(id).run());

        let sharedReportJson = null, myInsightJson = null, partnerInsightJson = null;
        try { sharedReportJson = row.shared_report_json ? JSON.parse(row.shared_report_json) : null; } catch (e) { sharedReportJson = null; }
        try { myInsightJson = row.my_insight_json ? JSON.parse(row.my_insight_json) : null; } catch (e) { myInsightJson = null; }
        try { partnerInsightJson = row.partner_insight_json ? JSON.parse(row.partner_insight_json) : null; } catch (e) { partnerInsightJson = null; }

        return jsonResponse({
          id: row.id,
          room_code: row.room_code,
          role: row.role,
          my_mira_type: row.my_mira_type,
          partner_mira_type: row.partner_mira_type,
          created_at: row.created_at,
          shared_report: sharedReportJson,
          my_insight: myInsightJson,
          partner_insight: partnerInsightJson,
        }, 200, origin);
      }

      // ══════════════════════════════════════════ 报告分享 API（统计分享次数） ══════════════════════════════════════════

      // 分享单人分析报告（POST /api/user/analyses/:id/share）
      if (path.match(/^\/api\/user\/analyses\/\d+\/share$/) && request.method === 'POST') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        const id = parseInt(path.split('/')[4], 10);
        if (!id) return jsonResponse({ error: '无效的记录ID' }, 400, origin);
        const row = await env.DB.prepare('SELECT id FROM single_analyses WHERE id = ? AND user_id = ?').bind(id, auth.uid).first();
        if (!row) return jsonResponse({ error: '记录不存在' }, 404, origin);
        await env.DB.prepare('UPDATE single_analyses SET share_count = share_count + 1 WHERE id = ?').bind(id).run();
        return jsonResponse({ success: true }, 200, origin);
      }

      // 分享双人房间记录（POST /api/user/rooms/:id/share）
      if (path.match(/^\/api\/user\/rooms\/\d+\/share$/) && request.method === 'POST') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        const id = parseInt(path.split('/')[4], 10);
        if (!id) return jsonResponse({ error: '无效的记录ID' }, 400, origin);
        const row = await env.DB.prepare('SELECT id FROM user_room_records WHERE id = ? AND user_id = ?').bind(id, auth.uid).first();
        if (!row) return jsonResponse({ error: '记录不存在' }, 404, origin);
        await env.DB.prepare('UPDATE user_room_records SET share_count = share_count + 1 WHERE id = ?').bind(id).run();
        return jsonResponse({ success: true }, 200, origin);
      }

      // 分享MIRA测试报告（POST /api/user/mira/:id/share）
      if (path.match(/^\/api\/user\/mira\/\d+\/share$/) && request.method === 'POST') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        const id = parseInt(path.split('/')[4], 10);
        if (!id) return jsonResponse({ error: '无效的记录ID' }, 400, origin);
        const row = await env.DB.prepare('SELECT id FROM mira_tests WHERE id = ? AND user_id = ?').bind(id, auth.uid).first();
        if (!row) return jsonResponse({ error: '记录不存在' }, 404, origin);
        await env.DB.prepare('UPDATE mira_tests SET share_count = share_count + 1 WHERE id = ?').bind(id).run();
        return jsonResponse({ success: true }, 200, origin);
      }

      // ══════════════════════════════════════════ 联系方式提交 API ══════════════════════════════════════════

      // 提交联系方式（POST /api/submit-contact）
      if (path === '/api/submit-contact' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'submit_contact', 5, 60000)) {
          return jsonResponse({ error: '提交过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { contact_type, contact_value, source, mira_type } = body;
        const validTypes = ['wechat', 'phone', 'email'];
        if (!contact_type || !validTypes.includes(contact_type)) {
          return jsonResponse({ error: 'contact_type 必须为 wechat/phone/email' }, 400, origin);
        }
        if (!contact_value || typeof contact_value !== 'string' || contact_value.trim().length === 0) {
          return jsonResponse({ error: 'contact_value 不能为空' }, 400, origin);
        }
        if (contact_value.length > 100) {
          return jsonResponse({ error: 'contact_value 过长' }, 400, origin);
        }

        const auth = await getAuthUser(request, env);
        const userId = auth && auth.uid ? auth.uid : null;

        await env.DB.prepare(
          'INSERT INTO user_contacts (user_id, contact_type, contact_value, source, mira_type, created_at) VALUES (?, ?, ?, ?, ?, datetime("now"))'
        ).bind(userId, contact_type, contact_value.trim(), source || '', mira_type || '').run();

        return jsonResponse({ success: true, message: '联系方式已提交' }, 200, origin);
      }

      // ══════════════════════════════════════════ 管理后台 API ══════════════════════════════════════════

      // 获取最近记录（GET /api/admin/records）
      if (path === '/api/admin/records' && request.method === 'GET') {
        try {
          const [analyses, tests, contacts, rooms] = await Promise.all([
            env.DB.prepare('SELECT * FROM single_analyses ORDER BY created_at DESC LIMIT 100').all(),
            env.DB.prepare('SELECT * FROM mira_tests ORDER BY created_at DESC LIMIT 100').all(),
            env.DB.prepare('SELECT * FROM user_contacts ORDER BY created_at DESC LIMIT 100').all(),
            env.DB.prepare('SELECT id, status, created_at FROM rooms ORDER BY created_at DESC LIMIT 100').all(),
          ]);

          return jsonResponse({
            single_analyses: analyses.results || [],
            mira_tests: tests.results || [],
            user_contacts: contacts.results || [],
            rooms: rooms.results || [],
          }, 200, origin);
        } catch (err) {
          console.error('admin/records error:', err.message);
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // ══════════════════════════════════════════ 后台管理 API ══════════════════════════════════════════

      // 后台管理页面（GET /admin）- 重定向到独立部署的管理页面
      if (path === '/admin' && request.method === 'GET') {
        const ipCheck = await checkAdminIP(request, env);
        if (!ipCheck.allowed) {
          await logSecurityEvent(env, 'login_fail', { reason: 'IP not whitelisted', ip: ipCheck.ip }, ipCheck.ip, '/admin', null, null);
          return new Response('Access Denied', { status: 403 });
        }
        return Response.redirect('https://mirrorsoul.top/admin.html', 302);
      }

      // 管理员登录（POST /api/admin/login）
      if (path === '/api/admin/login' && request.method === 'POST') {
        const ipCheck = await checkAdminIP(request, env);
        const clientIP = ipCheck.ip;
        if (!ipCheck.allowed) {
          await logSecurityEvent(env, 'login_fail', { reason: 'IP not whitelisted' }, clientIP, '/api/admin/login', null, null);
          return jsonResponse({ error: '访问被拒绝' }, 403, origin);
        }
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }
        const { username, password } = body;
        if (username !== 'admin') {
          await logSecurityEvent(env, 'login_fail', { reason: 'Invalid username', username }, clientIP, '/api/admin/login', null, null);
          return jsonResponse({ error: '用户名或密码错误' }, 401, origin);
        }
        const adminPassword = env.ADMIN_PASSWORD;
        if (!adminPassword) {
          return jsonResponse({ error: '管理员密码未配置' }, 500, origin);
        }
        if (password !== adminPassword) {
          await logSecurityEvent(env, 'login_fail', { reason: 'Invalid password' }, clientIP, '/api/admin/login', null, null);
          return jsonResponse({ error: '用户名或密码错误' }, 401, origin);
        }
        const token = await signAdminJWT(env, { sub: 'admin', role: 'admin' });
        await logSecurityEvent(env, 'admin_login', { success: true }, clientIP, '/api/admin/login', null, 'admin');
        return jsonResponse({ success: true, token, expireIn: 7200 }, 200, origin);
      }

      // 仪表盘数据（GET /api/admin/dashboard）
      if (path === '/api/admin/dashboard' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const today = new Date(); today.setHours(0, 0, 0, 0);
          const todayStr = today.toISOString().replace('T', ' ').substring(0, 19);
          const sevenDaysAgo = new Date(today.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').substring(0, 19);
          const thirtyDaysAgo = new Date(today.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString().replace('T', ' ').substring(0, 19);

          // 用户统计
          const totalUsers = await env.DB.prepare('SELECT COUNT(*) as cnt FROM users').first();
          const phoneUsers = await env.DB.prepare("SELECT COUNT(*) as cnt FROM users WHERE phone IS NOT NULL AND phone != ''").first();
          const guestUsers = await env.DB.prepare("SELECT COUNT(*) as cnt FROM users WHERE phone IS NULL OR phone = ''").first();
          const todayNewUsers = await env.DB.prepare("SELECT COUNT(*) as cnt FROM users WHERE created_at >= ?").bind(todayStr).first();
          const sevenDayNewUsers = await env.DB.prepare("SELECT COUNT(*) as cnt FROM users WHERE created_at >= ?").bind(sevenDaysAgo).first();
          const thirtyDayNewUsers = await env.DB.prepare("SELECT COUNT(*) as cnt FROM users WHERE created_at >= ?").bind(thirtyDaysAgo).first();

          // AI调用统计
          const aiCalls = await env.DB.prepare("SELECT endpoint, COUNT(*) as cnt FROM api_rate_limits WHERE endpoint IN ('chat','analyze','letter','mira_quiz','mira_deep') GROUP BY endpoint").all();
          const totalAiCalls = aiCalls.results ? aiCalls.results.reduce((s, r) => s + r.cnt, 0) : 0;

          // 短信统计
          const todaySms = await env.DB.prepare("SELECT COUNT(*) as cnt FROM sms_send_log WHERE created_at >= ?").bind(todayStr).first();
          const monthSms = await env.DB.prepare("SELECT COUNT(*) as cnt FROM sms_send_log WHERE created_at >= ?").bind(thirtyDaysAgo).first();
          const smsCost = (monthSms ? monthSms.cnt : 0) * 0.045;

          // 限流统计
          const rateLimitHits = await env.DB.prepare("SELECT COUNT(*) as cnt FROM api_rate_limits WHERE created_at_ms >= ?").bind(Date.now() - 86400000).first();

          // MIRA类型TOP5
          const miraTypes = await env.DB.prepare("SELECT mira_type, COUNT(*) as cnt FROM users WHERE mira_type IS NOT NULL AND mira_type != '' GROUP BY mira_type ORDER BY cnt DESC LIMIT 5").all();

          // 报告排行概览（各模块总数 + 查看/分享次数）
          const reportMira = await env.DB.prepare("SELECT COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM mira_tests").first();
          const reportSingle = await env.DB.prepare("SELECT COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM single_analyses").first();
          const reportCouple = await env.DB.prepare("SELECT COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM user_room_records").first();

          return jsonResponse({
            users: {
              total: totalUsers ? totalUsers.cnt : 0,
              phone: phoneUsers ? phoneUsers.cnt : 0,
              guest: guestUsers ? guestUsers.cnt : 0,
              todayNew: todayNewUsers ? todayNewUsers.cnt : 0,
              sevenDayNew: sevenDayNewUsers ? sevenDayNewUsers.cnt : 0,
              thirtyDayNew: thirtyDayNewUsers ? thirtyDayNewUsers.cnt : 0
            },
            ai: {
              total: totalAiCalls,
              byEndpoint: aiCalls.results || []
            },
            sms: {
              today: todaySms ? todaySms.cnt : 0,
              month: monthSms ? monthSms.cnt : 0,
              cost: Math.round(smsCost * 100) / 100
            },
            security: {
              rateLimit24h: rateLimitHits ? rateLimitHits.cnt : 0
            },
            miraTop5: miraTypes.results || [],
            reportSummary: {
              miraTests: { count: reportMira ? reportMira.cnt : 0, views: reportMira ? reportMira.views : 0, shares: reportMira ? reportMira.shares : 0 },
              singleAnalyses: { count: reportSingle ? reportSingle.cnt : 0, views: reportSingle ? reportSingle.views : 0, shares: reportSingle ? reportSingle.shares : 0 },
              coupleRooms: { count: reportCouple ? reportCouple.cnt : 0, views: reportCouple ? reportCouple.views : 0, shares: reportCouple ? reportCouple.shares : 0 }
            }
          }, 200, origin);
        } catch (e) {
          console.error('dashboard error:', e.message);
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 用户列表（GET /api/admin/users）
      if (path === '/api/admin/users' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const url = new URL(request.url);
          const page = parseInt(url.searchParams.get('page') || '1');
          const limit = parseInt(url.searchParams.get('limit') || '20');
          const keyword = url.searchParams.get('keyword') || '';
          const miraType = url.searchParams.get('miraType') || '';
          const status = url.searchParams.get('status') || '';
          const offset = (page - 1) * limit;

          let where = 'WHERE 1=1';
          const params = [];
          if (keyword) { where += " AND (nickname LIKE ? OR phone LIKE ? OR guest_id LIKE ?)"; params.push(`%${keyword}%`, `%${keyword}%`, `%${keyword}%`); }
          if (miraType) { where += " AND mira_type = ?"; params.push(miraType); }
          if (status) { where += " AND status = ?"; params.push(status); }

          const countResult = await env.DB.prepare(`SELECT COUNT(*) as cnt FROM users ${where}`).bind(...params).first();
          const total = countResult ? countResult.cnt : 0;

          const users = await env.DB.prepare(`SELECT id, guest_id, phone, nickname, mira_type, status, created_at, last_login_at FROM users ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).bind(...params, limit, offset).all();

          return jsonResponse({
            users: users.results || [],
            pagination: { page, limit, total, totalPages: Math.ceil(total / limit) }
          }, 200, origin);
        } catch (e) {
          console.error('admin users error:', e.message);
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 用户详情（GET /api/admin/users/:id）
      if (path.startsWith('/api/admin/users/') && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const userId = path.split('/').pop();
          const user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, status, created_at, last_login_at FROM users WHERE id = ?').bind(userId).first();
          if (!user) return jsonResponse({ error: '用户不存在' }, 404, origin);

          // 脱敏手机号
          const displayPhone = user.phone ? user.phone.substring(0, 3) + '****' + user.phone.substring(7) : null;

          // 获取分析记录
          const analyses = await env.DB.prepare('SELECT id, user_input, mira_type, created_at FROM single_analyses WHERE user_id = ? ORDER BY id DESC LIMIT 10').bind(userId).all();
          // 获取MIRA测试记录
          const tests = await env.DB.prepare('SELECT id, mira_type, deep_text, created_at FROM mira_tests WHERE user_id = ? ORDER BY id DESC LIMIT 10').bind(userId).all();
          // 获取双人房间记录
          const rooms = await env.DB.prepare('SELECT id, room_code, role, partner_mira_type, my_mira_type, created_at FROM user_room_records WHERE user_id = ? ORDER BY id DESC LIMIT 10').bind(userId).all();
          // 获取联系方式提交
          const contacts = await env.DB.prepare('SELECT id, contact_type, contact_value, created_at FROM user_contacts WHERE user_id = ? ORDER BY id DESC LIMIT 10').bind(userId).all();

          await logSecurityEvent(env, 'admin_action', { action: 'view_user_detail', userId }, request.headers.get('CF-Connecting-IP') || 'unknown', path, parseInt(userId), 'admin');

          return jsonResponse({
            user: { ...user, displayPhone },
            analyses: analyses.results || [],
            tests: tests.results || [],
            rooms: rooms.results || [],
            contacts: contacts.results || []
          }, 200, origin);
        } catch (e) {
          console.error('admin user detail error:', e.message);
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 封禁/解封用户（PUT /api/admin/users/:id/ban）
      if (path.match(/^\/api\/admin\/users\/\d+\/ban$/) && request.method === 'PUT') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const userId = path.split('/')[4];
          let body;
          try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }
          const { status } = body;
          if (status !== 'normal' && status !== 'banned') return jsonResponse({ error: '状态无效' }, 400, origin);
          await env.DB.prepare("UPDATE users SET status = ? WHERE id = ?").bind(status, userId).run();
          await logSecurityEvent(env, 'admin_action', { action: 'ban_user', userId, status }, request.headers.get('CF-Connecting-IP') || 'unknown', path, parseInt(userId), 'admin');
          return jsonResponse({ success: true, message: status === 'banned' ? '用户已封禁' : '用户已解封' }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '操作失败' }, 500, origin);
        }
      }

      // 重置用户密码（PUT /api/admin/users/:id/reset-pw）
      if (path.match(/^\/api\/admin\/users\/\d+\/reset-pw$/) && request.method === 'PUT') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const userId = path.split('/')[4];
          const salt = generateSalt();
          const hash = await hashPassword('1234', salt);
          await env.DB.prepare('UPDATE users SET password_hash = ?, password_salt = ? WHERE id = ?').bind(hash, salt, userId).run();
          await logSecurityEvent(env, 'admin_action', { action: 'reset_password', userId }, request.headers.get('CF-Connecting-IP') || 'unknown', path, parseInt(userId), 'admin');
          return jsonResponse({ success: true, message: '密码已重置为 1234' }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '操作失败' }, 500, origin);
        }
      }

      // AI调用统计（GET /api/admin/ai-stats）
      if (path === '/api/admin/ai-stats' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const url = new URL(request.url);
          const days = parseInt(url.searchParams.get('days') || '7');
          const fromDate = new Date(Date.now() - days * 86400000).toISOString().replace('T', ' ').substring(0, 19);
          const stats = await env.DB.prepare(
            "SELECT endpoint, COUNT(*) as cnt FROM api_rate_limits WHERE endpoint IN ('chat','analyze','letter','mira_quiz','mira_deep') AND created_at_ms >= ? GROUP BY endpoint"
          ).bind(Date.now() - days * 86400000).all();
          return jsonResponse({ stats: stats.results || [] }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 短信统计（GET /api/admin/sms-stats）
      if (path === '/api/admin/sms-stats' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const url = new URL(request.url);
          const days = parseInt(url.searchParams.get('days') || '30');
          const fromDate = new Date(Date.now() - days * 86400000).toISOString().replace('T', ' ').substring(0, 19);
          const dailyStats = await env.DB.prepare(
            "SELECT date(created_at) as date, COUNT(*) as cnt FROM sms_send_log WHERE created_at >= ? GROUP BY date(created_at) ORDER BY date DESC"
          ).bind(fromDate).all();
          const total = await env.DB.prepare("SELECT COUNT(*) as cnt FROM sms_send_log WHERE created_at >= ?").bind(fromDate).first();
          return jsonResponse({ daily: dailyStats.results || [], total: total ? total.cnt : 0, cost: Math.round((total ? total.cnt : 0) * 0.045 * 100) / 100 }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 报告统计排行（GET /api/admin/report-stats）
      // 双维度：按人格类型 + 按功能模块，含查看/分享次数
      if (path === '/api/admin/report-stats' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const url = new URL(request.url);
          const days = parseInt(url.searchParams.get('days') || '30');
          const fromDate = new Date(Date.now() - days * 86400000).toISOString().replace('T', ' ').substring(0, 19);

          // ═══ 维度一：按人格类型排行（含查看/分享次数） ═══

          // MIRA人格测试报告 - 按人格类型
          const miraTestByType = await env.DB.prepare(
            "SELECT mira_type, COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM mira_tests WHERE created_at >= ? AND mira_type IS NOT NULL AND mira_type != '' GROUP BY mira_type ORDER BY cnt DESC"
          ).bind(fromDate).all();

          // 单人对话分析报告 - 按人格类型
          const singleByType = await env.DB.prepare(
            "SELECT mira_type, COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM single_analyses WHERE created_at >= ? AND mira_type IS NOT NULL AND mira_type != '' GROUP BY mira_type ORDER BY cnt DESC"
          ).bind(fromDate).all();

          // 双人房间报告 - 按人格类型（取 my_mira_type）
          const coupleByType = await env.DB.prepare(
            "SELECT my_mira_type as mira_type, COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM user_room_records WHERE created_at >= ? AND my_mira_type IS NOT NULL AND my_mira_type != '' GROUP BY my_mira_type ORDER BY cnt DESC"
          ).bind(fromDate).all();

          // ═══ 维度二：按功能模块汇总 ═══

          const miraModule = await env.DB.prepare(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM mira_tests WHERE created_at >= ?"
          ).bind(fromDate).first();
          const singleModule = await env.DB.prepare(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM single_analyses WHERE created_at >= ?"
          ).bind(fromDate).first();
          const coupleModule = await env.DB.prepare(
            "SELECT COUNT(*) as cnt, COALESCE(SUM(view_count),0) as views, COALESCE(SUM(share_count),0) as shares FROM user_room_records WHERE created_at >= ?"
          ).bind(fromDate).first();

          return jsonResponse({
            byType: {
              miraTests: miraTestByType.results || [],
              singleAnalyses: singleByType.results || [],
              coupleRooms: coupleByType.results || []
            },
            byModule: {
              miraTests: { count: miraModule ? miraModule.cnt : 0, views: miraModule ? miraModule.views : 0, shares: miraModule ? miraModule.shares : 0 },
              singleAnalyses: { count: singleModule ? singleModule.cnt : 0, views: singleModule ? singleModule.views : 0, shares: singleModule ? singleModule.shares : 0 },
              coupleRooms: { count: coupleModule ? coupleModule.cnt : 0, views: coupleModule ? coupleModule.views : 0, shares: coupleModule ? coupleModule.shares : 0 }
            },
            totals: {
              miraTests: miraModule ? miraModule.cnt : 0,
              singleAnalyses: singleModule ? singleModule.cnt : 0,
              coupleRooms: coupleModule ? coupleModule.cnt : 0
            }
          }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 安全日志（GET /api/admin/security-logs）
      if (path === '/api/admin/security-logs' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const url = new URL(request.url);
          const page = parseInt(url.searchParams.get('page') || '1');
          const limit = parseInt(url.searchParams.get('limit') || '50');
          const eventType = url.searchParams.get('type') || '';
          const offset = (page - 1) * limit;

          let where = 'WHERE 1=1';
          const params = [];
          if (eventType) { where += " AND event_type = ?"; params.push(eventType); }

          const countResult = await env.DB.prepare(`SELECT COUNT(*) as cnt FROM security_logs ${where}`).bind(...params).first();
          const logs = await env.DB.prepare(`SELECT id, event_type, event_detail, ip, endpoint, user_id, admin_id, created_at FROM security_logs ${where} ORDER BY id DESC LIMIT ? OFFSET ?`).bind(...params, limit, offset).all();

          return jsonResponse({
            logs: logs.results || [],
            pagination: { page, limit, total: countResult ? countResult.cnt : 0 }
          }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // CSV导出（GET /api/admin/export/:type）
      if (path.startsWith('/api/admin/export/') && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const type = path.split('/').pop();
          let csv = '';
          let filename = '';

          if (type === 'users') {
            const users = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, status, created_at, last_login_at FROM users ORDER BY id DESC').all();
            filename = 'users.csv';
            csv = 'ID,GuestID,Phone,Nickname,MIRAType,Status,CreatedAt,LastLogin\n';
            for (const u of (users.results || [])) {
              csv += `${u.id},${u.guest_id || ''},"${u.phone || ''}","${u.nickname || ''}",${u.mira_type || ''},${u.status || ''},${u.created_at || ''},${u.last_login_at || ''}\n`;
            }
          } else if (type === 'security-logs') {
            const logs = await env.DB.prepare('SELECT id, event_type, event_detail, ip, endpoint, user_id, admin_id, created_at FROM security_logs ORDER BY id DESC').all();
            filename = 'security-logs.csv';
            csv = 'ID,EventType,Detail,IP,Endpoint,UserID,AdminID,CreatedAt\n';
            for (const l of (logs.results || [])) {
              csv += `${l.id},${l.event_type},"${(l.event_detail || '').replace(/"/g, '""')}",${l.ip},${l.endpoint || ''},${l.user_id || ''},${l.admin_id || ''},${l.created_at || ''}\n`;
            }
          } else {
            return jsonResponse({ error: '不支持的导出类型' }, 400, origin);
          }

          await logSecurityEvent(env, 'admin_action', { action: 'export', type }, request.headers.get('CF-Connecting-IP') || 'unknown', path, null, 'admin');

          return new Response(csv, {
            headers: {
              'Content-Type': 'text/csv; charset=utf-8',
              'Content-Disposition': `attachment; filename="${filename}"`,
              ...getCorsHeaders(origin)
            }
          });
        } catch (e) {
          return jsonResponse({ error: '导出失败' }, 500, origin);
        }
      }

      // 获取配置（GET /api/admin/config）
      if (path === '/api/admin/config' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          const whitelist = await getAdminConfig(env, 'ip_whitelist', []);
          return jsonResponse({ ipWhitelist: whitelist }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '查询失败' }, 500, origin);
        }
      }

      // 修改配置（PUT /api/admin/config）
      if (path === '/api/admin/config' && request.method === 'PUT') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        try {
          let body;
          try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }
          const { ipWhitelist } = body;
          if (!Array.isArray(ipWhitelist)) return jsonResponse({ error: 'IP白名单格式错误' }, 400, origin);
          await setAdminConfig(env, 'ip_whitelist', ipWhitelist);
          await logSecurityEvent(env, 'admin_action', { action: 'update_config', ipWhitelist }, request.headers.get('CF-Connecting-IP') || 'unknown', path, null, 'admin');
          return jsonResponse({ success: true }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: '操作失败' }, 500, origin);
        }
      }

      // 404
      return jsonResponse({ error: 'Not Found' }, 404, origin);

    } catch (err) {
      console.error('Worker error:', err.message, err.stack);
      return jsonResponse({ error: '服务器内部错误' }, 500, origin);
    }
  },
};

// ══════════════════════════════════════════ AI 调用 ══════════════════════════════════════════

// 带超时的 fetch
async function fetchWithTimeout(url, options, timeoutMs) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('FETCH_TIMEOUT')), timeoutMs);
    fetch(url, options)
      .then(res => { clearTimeout(timer); resolve(res); })
      .catch(err => { clearTimeout(timer); reject(err); });
  });
}

// 调用 Agnes AI（带超时、重试和错误处理）
async function callAI(env, prompt, mode, history, systemPromptOverride) {
  const systemPrompts = {
    single: '你是 Mirror，一个关系理解与表达操作系统。你擅长通过5层深度提问（事实→情绪→需求→意义→行动）来理解用户的情感关系状态。请严格以JSON格式回复（不要包含任何其他文字），包含以下字段：fact(事实摘要)、emotion(情绪识别)、need(核心需求)、misread(可能误读)、misreadType(误读类型：状态误读/行为误读/表达误读/自我投射)、status(关系状态评估)、before(用户原始的攻击性表达，一句典型的话)、innerThought(用户内心的真实想法)、after(Mirror翻译后的非暴力表达)、insight(深度洞察，2-3句话)、suggest(改善建议，具体可执行)、summary(一句话总结用户真正想表达的)、scores(对象，包含8个字段：expr_D表达暗影倾向1-15、expr_S表达柔光倾向1-15、expr_B表达明光倾向1-15、expr_R表达辉光倾向1-15、focus_O关注向外倾向1-15、focus_T关注朝向倾向1-15、focus_I关注倾向倾向1-15、focus_N关注向内倾向1-15。8个字段之和应为32，每个字段1-15，代表用户在关系中各维度的强度。D=暗影内敛/S=柔光温和/B=明光积极/R=辉光强烈，O=向外关注对方/T=朝向关系平衡/I=倾向自我反思/N=向内关注自我)。',
    couple: '你是 Mirror 的双人分析模块。请基于两个人的洞察摘要，生成共同报告JSON，包含：commonNeed(共同需求)、commonMisread(共同误读点)、interactionPattern(互动模式)、suggest(改善建议)。',
    letter: '你是 Mirror 的写信模块。你帮助用户以温柔、有同理心的方式表达难以说出口的情感。请以JSON格式回复，包含：empathy(共情回应)、suggestion(表达建议)、draft(信件草稿)。',
    quiz: '你是 MIRA 人格画像生成专家。用户的 MIRA 类型已经由计分系统确定，你的任务是基于用户的具体答案生成个性化描述。不要猜测或改变类型，直接使用用户提供的 miraType。请严格以JSON格式回复（不要包含任何其他文字），包含以下字段：miraType(直接使用用户提供的类型)、expression(表达方式维度的详细描述，1-2句话，基于用户在该维度的选择)、focus(关注方向维度的详细描述，1-2句话，基于用户在该维度的选择)、portrait(个性化人格画像描述，3-4句话，必须引用用户的具体选择，不是通用模板)、insight(亲密关系中的核心洞察，2-3句话)、suggest(改善关系的具体建议，2-3句话)。',
    deep: '你是 MIRA 人格深度解读专家。你基于用户的 MIRA 人格类型和关系数据，生成一段温暖、有洞察力的深度解读文章。请以纯文本格式回复（不要JSON，不要Markdown格式标记），直接输出文章正文。文章应包括：1. 这种人格类型在亲密关系中的核心模式；2. 这种模式下容易产生的冲突和误解；3. 如何发挥这种人格的优势来改善关系。用温暖、有同理心的口吻写，像一位懂你的朋友在谈心。',
    chat: `你是 Mirror，一位关系咨询师。你不是 AI 助手，不是心理诊断工具，不是裁判。你像一位真实、温暖、有经验的咨询师在和用户聊天。

核心原则：
- 理解 > 修复，追问 > 过早下结论，共情 > 评判，翻译 > 指责
- 不诊断、不标签化、不站队、不判断谁对谁错
- 不复述用户原话再问一遍，不一次抛多个问题
- 每次只问 1-2 个简短问题，问题要有方向性，基于用户回答动态调整
- 灵活代入用户具体内容提问，让用户感到你在认真听他说话

对话节奏（像真人咨询师）：
1. 先用 1 句话承接用户情绪（不要空洞的"我理解你"，要具体指向用户说的内容，引用用户原话中的关键词）
2. 再基于依恋理论判断当前最该追问的方向：
   - 安全型信号（能清晰表达感受和需求）→ 探索意义层或行动层
   - 焦虑型信号（害怕失去、过度关注对方反应）→ 先稳定安全感，问"你此刻最害怕的是什么"
   - 回避型信号（回避感受、只讲事实不讲情绪）→ 温和引导感受层，问"那件事发生时你身体有什么感觉"
   - 混乱型信号（矛盾、混乱表达）→ 先帮整理事实，问"这件事最开始是什么时候"
3. 每轮回复控制在 2-4 句话，不超过 80 字。不要长篇大论。

追问策略（动态调整，不固定顺序）：
- 用户说了很多感受但缺少具体事实 → 问"能给我举个例子吗"或"具体是哪一次"
- 用户只说事实没说感受 → 问"那时候你心里是什么感觉"或"你身体有什么反应"
- 用户事实+感受都有了但没说需求 → 问"你真正想要的是什么"或"你最希望对方给你什么"
- 用户三个维度都有但想继续聊 → 继续对话，直到用户满意

判断何时信息足够：
- 信息充足标准：具体事实（发生了什么）+ 情绪感受（当下的感受）+ 核心需求（真正想要什么）
- 当三个维度都有明确信息时，给用户选择权：设置 action 为 "offer_analyze"
- offer_analyze 时回复："聊了这么多，信息看起来够了。我来帮你梳理一下？还是你想再聊聊？"
- 如果用户选继续聊，继续追问或倾听
- 软上限 50 轮，第 50 轮自动切换到 analyze（"聊了这么多，我来帮你梳理一下"）
- 如果信息不充足，继续追问缺失维度，同时给用户暗示方向

处理敷衍/恶意输入：
- 如果用户回答很敷衍（只回"嗯""还好""不知道"），尝试换一种问法，给具体方向引导
- 如果用户明显恶意（无意义文字、辱骂、挑衅），礼貌拒绝："Mirror 是帮助理解关系困惑的。如果你愿意说说发生了什么，我会认真听。"
- 如果用户连续 2 轮敷衍，第 3 轮尝试最后一问，第 4 轮自动出报告

绝对限制：
- 禁止心理诊断、人格标签化结论
- 禁止 PUA、操控、冷暴力、断联套路建议
- 禁止把推测写成事实
- 如果出现家暴、自伤、自杀等高风险内容，立即停止常规对话，优先确认安全

输出格式（严格 JSON，不要 Markdown 代码块，不要额外说明文字）：

当 action 为 "ask" 时（继续追问）：
{"reply":"你对用户说的自然语言回复（2-4句话，先承接情绪再追问）","action":"ask","followUp":["1-2个追问问题"],"attachment":{"emotion":"识别到的核心情绪","dimension":"fact|emotion|need|meaning|action","sufficientSignals":{"hasFact":false,"hasEmotion":false,"hasNeed":false},"round":1}}

当 action 为 "offer_analyze" 时（信息充足，给用户选择权）：
{"reply":"聊了这么多，信息看起来够了。我来帮你梳理一下？还是你想再聊聊？","action":"offer_analyze","followUp":[],"attachment":{"emotion":"","dimension":"","sufficientSignals":{"hasFact":true,"hasEmotion":true,"hasNeed":true},"round":2}}

当 action 为 "analyze" 时（出报告）：
{"reply":"聊了这么多，我来帮你梳理一下。","action":"analyze","followUp":[],"attachment":{"emotion":"","dimension":"","sufficientSignals":{"hasFact":true,"hasEmotion":true,"hasNeed":true},"round":3}}`,
    quote: '你是一位有洞察力的文案专家。请直接输出一句金句（20-40字），像朋友说的心里话，带一点自嘲或反差。只输出金句本身，不要引号不要解释。',
  };

  const basePrompt = systemPrompts[mode] || systemPrompts.single;
  const systemPrompt = systemPromptOverride ? basePrompt + '\n\n【当前阶段任务】' + systemPromptOverride : basePrompt;

  const messages = [
    { role: 'system', content: systemPrompt },
    ...(history || []),
    { role: 'user', content: prompt },
  ];

  const maxRetries = 2;
  const timeoutMs = 15000;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let response;
    try {
      response = await fetchWithTimeout('https://api.deepseek.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.AI_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'deepseek-v4-flash',
          messages,
          temperature: 0.15,
          max_tokens: 2000,
        }),
      }, timeoutMs);
    } catch (e) {
      if (e.message === 'FETCH_TIMEOUT') {
        if (attempt < maxRetries) {
          await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
          continue;
        }
        return { error: 'AI 服务响应超时，请稍后重试', raw: null };
      }
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 1000 * (attempt + 1)));
        continue;
      }
      return { error: 'AI 服务连接失败', raw: null };
    }

    // 对 502/503/504/429 错误进行重试
    if (!response.ok) {
      const status = response.status;
      if ((status === 502 || status === 503 || status === 504 || status === 429) && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      return { error: `AI 服务返回错误 (${status})`, raw: null };
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content || '';

    if (!content) {
      return { error: 'AI 返回内容为空', raw: null };
    }

    // deep / quote 模式预期纯文本，直接返回 raw
    if (mode === 'deep' || mode === 'quote') {
      return { raw: content };
    }

    // 其他模式尝试解析 JSON
    try {
      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        return JSON.parse(jsonMatch[0]);
      }
    } catch (e) {
      // 解析失败
    }

    // chat 模式：JSON 解析失败时，将纯文本包装为有效响应（避免 500 导致前端降级）
    if (mode === 'chat') {
      return {
        reply: content,
        action: 'ask',
        followUp: [],
        attachment: { emotion: '', dimension: '', sufficientSignals: { hasFact: false, hasEmotion: false, hasNeed: false }, round: 1 }
      };
    }

    return { raw: content, error: 'JSON解析失败' };
  }

  return { error: 'AI 服务暂时不可用，请稍后重试', raw: null };
}

// 双人分析：分别分析 A 和 B（AES-GCM 解密 + Base64 兼容）
async function analyzeCouple(env, code) {
  try {
    const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
    if (!room || !room.a_input || !room.b_input) {
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'analyzing'").bind(code).run();
      return;
    }

    // AES-GCM 解密原文（兼容旧 Base64 格式）
    let aText, bText;
    try {
      aText = await decryptText(env, room.a_input);
      if (!aText) aText = decodeURIComponent(escape(atob(room.a_input))); // 向下兼容旧数据
      bText = await decryptText(env, room.b_input);
      if (!bText) bText = decodeURIComponent(escape(atob(room.b_input))); // 向下兼容旧数据
    } catch (e) {
      console.error('Decrypt failed, trying base64 fallback:', e.message);
      aText = decodeURIComponent(escape(atob(room.a_input)));
      bText = decodeURIComponent(escape(atob(room.b_input)));
    }

    // 分别分析 A 和 B
    const [aResult, bResult] = await Promise.all([
      callAI(env, `分析以下用户的情感关系描述，提取核心信息：${aText}`, 'single', []),
      callAI(env, `分析以下用户的情感关系描述，提取核心信息：${bText}`, 'single', []),
    ]);

    if (aResult.error || bResult.error) {
      console.error('AI analysis failed:', { a: aResult.error, b: bResult.error });
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ?").bind(code).run();
      return;
    }

    const aInsight = JSON.stringify({
      fact: aResult.fact || '',
      emotion: aResult.emotion || '',
      need: aResult.need || '',
      misread: aResult.misread || '',
      status: aResult.status || '',
      miraType: aResult.miraType || '',
    });

    const bInsight = JSON.stringify({
      fact: bResult.fact || '',
      emotion: bResult.emotion || '',
      need: bResult.need || '',
      misread: bResult.misread || '',
      status: bResult.status || '',
      miraType: bResult.miraType || '',
    });

    await env.DB.prepare(
      'UPDATE rooms SET a_insight = ?, b_insight = ?, status = ? WHERE id = ?'
    ).bind(aInsight, bInsight, 'analyzed', code).run();
  } catch (err) {
    console.error('analyzeCouple error:', err.message);
    await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'analyzing'").bind(code).run();
  }
}

// 生成共同报告（带错误处理）
async function generateSharedReport(env, code) {
  try {
    const room = await env.DB.prepare('SELECT a_insight, b_insight FROM rooms WHERE id = ?').bind(code).first();
    if (!room || !room.a_insight || !room.b_insight) return;

    const aInsight = JSON.parse(room.a_insight || '{}');
    const bInsight = JSON.parse(room.b_insight || '{}');

    const prompt = `基于以下两个人的洞察摘要，生成共同建议：

A的核心需求：${aInsight.need || '未知'}
A的误读：${aInsight.misread || '未知'}
A的情绪：${aInsight.emotion || '未知'}
A的MIRA类型：${aInsight.miraType || 'ST'}

B的核心需求：${bInsight.need || '未知'}
B的误读：${bInsight.misread || '未知'}
B的情绪：${bInsight.emotion || '未知'}
B的MIRA类型：${bInsight.miraType || 'BO'}

请生成共同报告，包含：
1. 共同需求
2. 共同误读点
3. 互动模式
4. 可执行的改善方向
5. 将A和B的MIRA类型原样透传（aMiraType和bMiraType字段）

输出 JSON：{"commonNeed":"","commonMisread":"","interactionPattern":"","suggest":"","aMiraType":"${aInsight.miraType || 'ST'}","bMiraType":"${bInsight.miraType || 'BO'}"}`;

    const result = await callAI(env, prompt, 'couple', []);

    if (result.error) {
      console.error('Shared report generation failed:', result.error);
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'analyzed'").bind(code).run();
      return;
    }

    await env.DB.prepare(
      'UPDATE rooms SET shared_report = ?, status = ? WHERE id = ?'
    ).bind(JSON.stringify(result), 'completed', code).run();

    // 报告生成成功后，复制房间记录到 a/b 双方的 user_room_records（永久保存）
    try {
      await copyRoomToUserRecords(env, code);
    } catch (copyErr) {
      console.error('copyRoomToUserRecords error:', copyErr.message);
    }
  } catch (err) {
    console.error('generateSharedReport error:', err.message);
    await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'analyzed'").bind(code).run();
  }
}

// 异步保存单人分析结果到 single_analyses 表（同时写入 analysis_history 和 insight_diaries）
async function saveSingleAnalysis(env, prompt, result, uid = null) {
  try {
    const userInput = (prompt || '').substring(0, 500);
    // 把完整 AI 结果 JSON 序列化存入 report_json
    let reportJson = '{}';
    try { reportJson = JSON.stringify(result); } catch (e) { reportJson = '{}'; }
    const insertResult = await env.DB.prepare(
      'INSERT INTO single_analyses (user_input, fact, emotion, need, misread, status, insight, suggest, mira_type, user_id, report_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
    ).bind(
      userInput,
      result.fact || '',
      result.emotion || '',
      result.need || '',
      result.misread || '',
      result.status || '',
      result.insight || '',
      result.suggest || '',
      result.miraType || '',
      uid,
      reportJson,
    ).run();

    // 同步写入 analysis_history（用于动态画像趋势追踪）
    if (uid) {
      const sourceId = insertResult.meta ? insertResult.meta.last_row_id : null;
      let dimsJson = '{}';
      try {
        if (result.scores) {
          dimsJson = JSON.stringify({
            expr_D: result.scores.expr_D || 0,
            expr_S: result.scores.expr_S || 0,
            expr_B: result.scores.expr_B || 0,
            expr_R: result.scores.expr_R || 0,
            focus_O: result.scores.focus_O || 0,
            focus_T: result.scores.focus_T || 0,
            focus_I: result.scores.focus_I || 0,
            focus_N: result.scores.focus_N || 0,
          });
        }
      } catch (e) { /* scores 解析失败 */ }

      try {
        await env.DB.prepare(
          'INSERT INTO analysis_history (user_id, source_type, source_id, mira_type, dimensions_json, insight_summary, emotion_snapshot, need_snapshot, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
        ).bind(
          uid,
          'single',
          sourceId,
          result.miraType || '',
          dimsJson,
          (result.insight || '').substring(0, 200),
          (result.emotion || '').substring(0, 100),
          (result.need || '').substring(0, 100),
        ).run();
      } catch (e) { console.error('analysis_history insert error:', e.message); }

      // 写入洞察日记
      try {
        let diaryText = result.insight || result.summary || '';
        if (diaryText.length > 0) {
          await env.DB.prepare(
            'INSERT INTO insight_diaries (user_id, source_type, source_id, diary_text, emotion_tag, growth_tag, created_at) VALUES (?, ?, ?, ?, ?, ?, datetime("now"))'
          ).bind(
            uid,
            'analyze',
            sourceId,
            diaryText.substring(0, 200),
            (result.emotion || '').substring(0, 50),
            '自我觉察',
          ).run();
        }
      } catch (e) { console.error('insight_diaries insert error:', e.message); }
    }
  } catch (err) {
    console.error('saveSingleAnalysis error:', err.message);
  }
}

// 复制房间记录到 a/b 双方的 user_room_records（永久保存，防重复）
async function copyRoomToUserRecords(env, code) {
  const room = await env.DB.prepare('SELECT a_uid, b_uid, a_insight, b_insight, shared_report, expires_at FROM rooms WHERE id = ?').bind(code).first();
  if (!room) return;

  const sharedReport = room.shared_report || '{}';
  let aInsight = null, bInsight = null;
  try { aInsight = room.a_insight ? JSON.parse(room.a_insight) : null; } catch (e) { aInsight = null; }
  try { bInsight = room.b_insight ? JSON.parse(room.b_insight) : null; } catch (e) { bInsight = null; }

  const aInsightRaw = room.a_insight || '{}';
  const bInsightRaw = room.b_insight || '{}';

  // 为 A 端复制
  if (room.a_uid) {
    const existA = await env.DB.prepare('SELECT id FROM user_room_records WHERE room_code = ? AND user_id = ?').bind(code, room.a_uid).first();
    if (!existA) {
      await env.DB.prepare(
        'INSERT INTO user_room_records (user_id, room_code, role, my_mira_type, partner_mira_type, shared_report_json, my_insight_json, partner_insight_json, created_at, source_room_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now"), ?)'
      ).bind(
        room.a_uid,
        code,
        'a',
        (aInsight && aInsight.miraType) || '',
        (bInsight && bInsight.miraType) || '',
        sharedReport,
        aInsightRaw,
        bInsightRaw,
        room.expires_at || null,
      ).run();
    }
  }

  // 为 B 端复制
  if (room.b_uid) {
    const existB = await env.DB.prepare('SELECT id FROM user_room_records WHERE room_code = ? AND user_id = ?').bind(code, room.b_uid).first();
    if (!existB) {
      await env.DB.prepare(
        'INSERT INTO user_room_records (user_id, room_code, role, my_mira_type, partner_mira_type, shared_report_json, my_insight_json, partner_insight_json, created_at, source_room_expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime("now"), ?)'
      ).bind(
        room.b_uid,
        code,
        'b',
        (bInsight && bInsight.miraType) || '',
        (aInsight && aInsight.miraType) || '',
        sharedReport,
        bInsightRaw,
        aInsightRaw,
        room.expires_at || null,
      ).run();
    }
  }
}
