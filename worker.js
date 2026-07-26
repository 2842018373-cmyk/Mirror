// ══════════════════════════════════════════ Mirror API Worker v3 ══════════════════════════════════════════
// Cloudflare Workers + D1 后端
// v3: 安全加固 + 数据隔离 + 认证系统 + AES加密 + 服务端验证码

// CORS 白名单
const ALLOWED_ORIGINS = [
  'https://mirrorsoul.top',
  'https://www.mirrorsoul.top',
  'https://api.mirrorsoul.top',
  'https://6a3552b7d62c5c239e40dcfc.vercel.app',
  'https://mirror-15a.pages.dev',
  'https://mirror.2842018373-cmyk.pages.dev',
  'http://localhost:5500',
  'http://localhost:3000',
  'http://127.0.0.1:5500',
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

// 简易速率限制（基于 IP + 端点，内存级，适合 Workers 单实例）
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
        let user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, created_at FROM users WHERE guest_id = ?').bind(guestId).first();

        if (!user) {
          await env.DB.prepare('INSERT INTO users (guest_id, created_at, last_login_at) VALUES (?, datetime("now"), datetime("now"))').bind(guestId).run();
          user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, created_at FROM users WHERE guest_id = ?').bind(guestId).first();
        } else {
          await env.DB.prepare('UPDATE users SET last_login_at = datetime("now") WHERE id = ?').bind(user.id).run();
        }

        const token = await createJWT(env, { uid: user.id, gid: guestId, phone: null });
        return jsonResponse({ success: true, token, isGuest: true, user: { id: user.id, phone: null, nickname: user.nickname } }, 200, origin);
      }

      // 密码登录（POST /api/auth/password-login）
      if (path === '/api/auth/password-login' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'password_login', 10, 60000)) {
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
        let user = await env.DB.prepare('SELECT id, phone, password_hash, password_salt, nickname, mira_type, guest_id FROM users WHERE phone = ?').bind(phone).first();
        if (!user) {
          // 自动注册：创建用户并设置默认密码
          const salt = generateSalt();
          const hash = await hashPassword(DEFAULT_PASSWORD, salt);
          await env.DB.prepare('INSERT INTO users (phone, password_hash, password_salt, created_at, last_login_at) VALUES (?, ?, ?, datetime("now"), datetime("now"))').bind(phone, hash, salt).run();
          user = await env.DB.prepare('SELECT id, phone, password_hash, password_salt, nickname, mira_type, guest_id FROM users WHERE phone = ?').bind(phone).first();
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
          user: { id: user.id, phone: user.phone, nickname: user.nickname }
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
        if (!checkRateLimit(clientIP, 'sms_login', 10, 60000)) {
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
        let user = await env.DB.prepare('SELECT id, phone, nickname, mira_type, guest_id FROM users WHERE phone = ?').bind(phone).first();
        if (!user) {
          // 新用户：自动注册
          await env.DB.prepare('INSERT INTO users (phone, created_at, last_login_at) VALUES (?, datetime("now"), datetime("now"))').bind(phone).run();
          user = await env.DB.prepare('SELECT id, phone, nickname, mira_type, guest_id FROM users WHERE phone = ?').bind(phone).first();
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
          user: { id: user.id, phone: user.phone, nickname: user.nickname, miraType: user.mira_type, isGuest: false }
        }, 200, origin);
      }

      // 绑定手机号（POST /api/auth/bind-phone）
      if (path === '/api/auth/bind-phone' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'bind_phone', 5, 60000)) {
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
        await env.DB.prepare('UPDATE users SET phone = ?, last_login_at = datetime("now") WHERE id = ?').bind(phone, payload.uid).run();
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
          const user = await env.DB.prepare('SELECT id, guest_id, phone, nickname, mira_type, created_at FROM users WHERE id = ?').bind(payload.uid).first();
          if (!user) {
            return jsonResponse({ error: '用户不存在' }, 404, origin);
          }
          return jsonResponse({ success: true, user: { id: user.id, phone: user.phone, nickname: user.nickname, miraType: user.mira_type, isGuest: !user.phone } }, 200, origin);
        } catch (e) {
          return jsonResponse({ error: 'Token已过期' }, 401, origin);
        }
      }

      // ══════════════════════════════════════════ 房间管理 API ══════════════════════════════════════════

      // 创建房间（速率限制：每 IP 每分钟 5 次）
      if (path === '/api/room' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'create_room', 5, 60000)) {
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

      // 单人模式 AI 分析（速率限制：每 IP 每分钟 10 次）
      if (path === '/api/analyze' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'analyze', 10, 60000)) {
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
        if (!checkRateLimit(clientIP, 'letter', 10, 60000)) {
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
        if (!checkRateLimit(clientIP, 'mira_quiz', 5, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt, scores, answers } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 15000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        // 尝试从请求头拿 uid
        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        const result = await callAI(env, prompt, 'quiz', []);

        // AI 返回成功且有 uid，异步保存到 mira_tests 表 + 更新 users.mira_type
        if (uid && !result.error && result.miraType) {
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
                result.miraType || '',
                result.expression || '',
                result.focus || '',
                result.portrait || '',
                scoresJson,
                answersJson,
              ).run();

              // 同时更新 users.mira_type
              await env.DB.prepare('UPDATE users SET mira_type = ? WHERE id = ?').bind(result.miraType || '', uid).run();
            } catch (err) {
              console.error('saveMiraTest error:', err.message);
            }
          })());
        }

        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // MIRA 深度解读
      if (path === '/api/mira-deep' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'mira_deep', 5, 60000)) {
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
              contact_type TEXT NOT NULL,
              contact_value TEXT NOT NULL,
              source TEXT DEFAULT '',
              mira_type TEXT DEFAULT '',
              created_at TEXT DEFAULT (datetime('now'))
            )
          `).run();

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

          // 个人中心索引
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_single_analyses_user ON single_analyses(user_id, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_mira_tests_user ON mira_tests(user_id, created_at)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_user_room_records_user ON user_room_records(user_id, created_at)').run();

          // 为老 users 表添加密码字段（如果不存在）
          try { await env.DB.prepare('ALTER TABLE users ADD COLUMN password_hash TEXT').run(); } catch(e) { /* 字段已存在 */ }
          try { await env.DB.prepare('ALTER TABLE users ADD COLUMN password_salt TEXT').run(); } catch(e) { /* 字段已存在 */ }

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

      // 修改密码（PUT /api/user/password）
      if (path === '/api/user/password' && request.method === 'PUT') {
        if (!checkRateLimit(clientIP, 'change_password', 5, 60000)) {
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
        if (!checkRateLimit(clientIP, 'phone_send_code', 5, 60000)) {
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
        if (!checkRateLimit(clientIP, 'phone_change', 5, 60000)) {
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

      // ══════════════════════════════════════════ 联系方式提交 API ══════════════════════════════════════════

      // 提交联系方式（POST /api/submit-contact）
      if (path === '/api/submit-contact' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'submit_contact', 5, 60000)) {
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

        await env.DB.prepare(
          'INSERT INTO user_contacts (contact_type, contact_value, source, mira_type, created_at) VALUES (?, ?, ?, ?, datetime("now"))'
        ).bind(contact_type, contact_value.trim(), source || '', mira_type || '').run();

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
async function callAI(env, prompt, mode, history) {
  const systemPrompts = {
    single: '你是 Mirror，一个关系理解与表达操作系统。你擅长通过5层深度提问（事实→情绪→需求→意义→行动）来理解用户的情感关系状态。请严格以JSON格式回复（不要包含任何其他文字），包含以下字段：fact(事实摘要)、emotion(情绪识别)、need(核心需求)、misread(可能误读)、misreadType(误读类型：状态误读/行为误读/表达误读/自我投射)、status(关系状态评估)、before(用户原始的攻击性表达，一句典型的话)、innerThought(用户内心的真实想法)、after(Mirror翻译后的非暴力表达)、insight(深度洞察，2-3句话)、suggest(改善建议，具体可执行)、summary(一句话总结用户真正想表达的)、scores(对象，包含8个字段：expr_D表达暗影倾向1-15、expr_S表达柔光倾向1-15、expr_B表达明光倾向1-15、expr_R表达辉光倾向1-15、focus_O关注向外倾向1-15、focus_T关注朝向倾向1-15、focus_I关注倾向倾向1-15、focus_N关注向内倾向1-15。8个字段之和应为32，每个字段1-15，代表用户在关系中各维度的强度。D=暗影内敛/S=柔光温和/B=明光积极/R=辉光强烈，O=向外关注对方/T=朝向关系平衡/I=倾向自我反思/N=向内关注自我)。',
    couple: '你是 Mirror 的双人分析模块。请基于两个人的洞察摘要，生成共同报告JSON，包含：commonNeed(共同需求)、commonMisread(共同误读点)、interactionPattern(互动模式)、suggest(改善建议)。',
    letter: '你是 Mirror 的写信模块。你帮助用户以温柔、有同理心的方式表达难以说出口的情感。请以JSON格式回复，包含：empathy(共情回应)、suggestion(表达建议)、draft(信件草稿)。',
    quiz: '你是 MIRA 人格画像生成专家。用户的 MIRA 类型已经由计分系统确定，你的任务是基于用户的具体答案生成个性化描述。不要猜测或改变类型，直接使用用户提供的 miraType。请严格以JSON格式回复（不要包含任何其他文字），包含以下字段：miraType(直接使用用户提供的类型)、expression(表达方式维度的详细描述，1-2句话，基于用户在该维度的选择)、focus(关注方向维度的详细描述，1-2句话，基于用户在该维度的选择)、portrait(个性化人格画像描述，3-4句话，必须引用用户的具体选择，不是通用模板)、insight(亲密关系中的核心洞察，2-3句话)、suggest(改善关系的具体建议，2-3句话)。',
    deep: '你是 MIRA 人格深度解读专家。你基于用户的 MIRA 人格类型和关系数据，生成一段温暖、有洞察力的深度解读文章。请以纯文本格式回复（不要JSON，不要Markdown格式标记），直接输出文章正文。文章应包括：1. 这种人格类型在亲密关系中的核心模式；2. 这种模式下容易产生的冲突和误解；3. 如何发挥这种人格的优势来改善关系。用温暖、有同理心的口吻写，像一位懂你的朋友在谈心。',
  };

  const systemPrompt = systemPrompts[mode] || systemPrompts.single;

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
      response = await fetchWithTimeout('https://apihub.agnes-ai.com/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${env.AI_API_KEY}`,
        },
        body: JSON.stringify({
          model: 'agnes-1.5-flash',
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

    // deep 模式预期纯文本，直接返回 raw
    if (mode === 'deep') {
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

// 异步保存单人分析结果到 single_analyses 表
async function saveSingleAnalysis(env, prompt, result, uid = null) {
  try {
    const userInput = (prompt || '').substring(0, 500);
    // 把完整 AI 结果 JSON 序列化存入 report_json
    let reportJson = '{}';
    try { reportJson = JSON.stringify(result); } catch (e) { reportJson = '{}'; }
    await env.DB.prepare(
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
