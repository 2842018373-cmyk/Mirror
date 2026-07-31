// ══════════════════════════════════════════ Mirror API Worker v3 ══════════════════════════════════════════
// Cloudflare Workers + D1 后端
// v3: 安全加固 + 数据隔离 + 认证系统 + AES加密 + 服务端验证码

// ═══ Base64 编码/解码工具（处理中文）═══
function base64Encode(str) {
  if (!str) return '';
  try {
    const utf8Bytes = new TextEncoder().encode(str);
    let binary = '';
    utf8Bytes.forEach(b => binary += String.fromCharCode(b));
    return btoa(binary);
  } catch (e) { return str; }
}
function base64Decode(str) {
  if (!str) return '';
  try {
    const binary = atob(str);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder().decode(bytes);
  } catch (e) { return str; }
}

// CORS 白名单（仅生产域名，移除测试域名减少攻击面）
const ALLOWED_ORIGINS = [
  'https://mirrorsoul.top',
  'https://www.mirrorsoul.top',
];

// ═══ 双人模式18维度问卷定义 ═══
// 5大维度 × 3-4题 = 18题，每题可填"无"跳过（必答题除外）
const COUPLE_DIMENSIONS = [
  // ── 事实（4题）── 聚焦到一件具体的事
  { id: 'd1', group: 'fact', label: '最近一次让你心里不舒服的具体事情是什么？', hint: '就一件具体的事，越具体越好', placeholder: '例：上周五晚上，他回来后一直看手机，我跟他说话他没抬头', required: true },
  { id: 'd2', group: 'fact', label: '当时是什么时间、在什么场景下发生的？', hint: '什么时候、在哪里、还有谁在场', placeholder: '例：晚上九点多，在家客厅，就我们两个人' },
  { id: 'd3', group: 'fact', label: '事情是怎么发展到让你难受的那一步的？', hint: '从开始到难受，中间发生了什么', placeholder: '例：我先问他吃饭没，他嗯了一声没看我，我又说了一件事他还是没反应，我就不想说话了' },
  { id: 'd4', group: 'fact', label: '对方做了什么、说了什么，让你产生了这种感受？', hint: '具体描述对方的言行，不用分析原因', placeholder: '例：他盯着手机说了句"你别老盯着我不行吗"，语气很不耐烦' },
  // ── 情绪（4题）──
  { id: 'd5', group: 'emotion', label: '当时你内心的第一反应是什么？', hint: '不是想法，是感受', placeholder: '例：心里一下子凉了…', required: true },
  { id: 'd6', group: 'emotion', label: '你身体有什么感受？', hint: '紧绷/胸闷/流泪/麻木等', placeholder: '例：胸口堵得慌，手心出汗…' },
  { id: 'd7', group: 'emotion', label: '这种感觉持续了多久？', hint: '一阵子还是一直', placeholder: '例：那之后好几天都提不起精神…' },
  { id: 'd8', group: 'emotion', label: '如果用一种颜色形容那种感觉，会是什么？', hint: '不需要解释为什么', placeholder: '例：灰蓝色，像阴天…' },
  // ── 需求（4题）── 用具体场景引导用户说出需求
  { id: 'd9', group: 'need', label: '如果对方做了一件事就能让你好受一些，你希望TA做什么？', hint: '不是大道理，是一件具体的小事', placeholder: '例：哪怕只是问我一句"今天还好吗"', required: true },
  { id: 'd10', group: 'need', label: '这件事里，你最希望被对方怎么对待？', hint: '想想你被好好对待过的时刻', placeholder: '例：希望TA能先听我说完，不要急着反驳' },
  { id: 'd11', group: 'need', label: '你现在的担心是什么？如果这个担心消失了会怎样？', hint: '你心里一直在怕什么', placeholder: '例：我怕TA根本不在乎我的感受，如果不在了我会松一口气' },
  { id: 'd12', group: 'need', label: '如果这件事一直没解决，你最害怕失去的是什么？', hint: '最坏的结果是什么', placeholder: '例：怕我们越来越没话说，最后变成陌生人' },
  // ── 误读（3题）──
  { id: 'd13', group: 'misread', label: '你觉得TA当时那么做，是什么意思？', hint: '你对TA行为的解读', placeholder: '例：我觉得TA就是不在乎我…', required: true },
  { id: 'd14', group: 'misread', label: '在你看来，TA为什么会那样反应？', hint: '你猜测的原因', placeholder: '例：可能TA觉得我太啰嗦了吧…' },
  { id: 'd15', group: 'misread', label: '你觉得你们之间最大的误解可能在哪里？', hint: '不是谁对谁错，是哪里错位了', placeholder: '例：我说的关心，TA可能觉得是控制…' },
  // ── 行动/关系（3题）──
  { id: 'd16', group: 'action', label: '你尝试过什么来改善？', hint: '做过什么努力', placeholder: '例：我试过跟TA好好谈，但每次都不欢而散…', required: true },
  { id: 'd17', group: 'action', label: '如果能重新来过，你会怎么做？', hint: '回头看的新视角', placeholder: '例：可能我不会用那种语气说…' },
  { id: 'd18', group: 'action', label: '你希望这段关系最终变成什么样？', hint: '你理想中的状态', placeholder: '例：不需要完美，但希望能好好说话…' },
];

// ═══ 关系原型规则引擎：4表达模式 × 4投射模式 = 16种核心互动结构 ═══
// 表达模式: B(Bearer/明光) D(Discoverer/暗影) R(Reflector/柔光) S(Seeker/辉光)
// 投射模式: I(Internalizing/向内) N(Neutral/中性) O(Outward/向外) T(Targeting/朝向)
const RELATIONSHIP_ARCHETYPES = {
  // 表达模式互动 (4×4=16) — 用双方表达模式的组合映射到4种互动
  // BB: 双方都直接表达 → 碰撞型
  // BD/DB: 一方直接一方内敛 → 追逃型
  // BR/RB: 一方直接一方克制 → 引导型
  // BS/SB: 一方直接一方压抑 → 爆发型
  // DD: 双方都内敛 → 沉默型
  // DR/RD: 一方内敛一方克制 → 缓流型
  // DS/SD: 一方内敛一方压抑 → 冰封型
  // RR: 双方都克制 → 礼貌型
  // RS/SR: 一方克制一方压抑 → 隐忍型
  // SS: 双方都压抑 → 窒息型
  'BB': { name: '碰撞火焰', pattern: '直接对直接', desc: '双方都习惯直接表达，互动中充满火花。优势是沟通效率高，风险是容易升级为正面冲突。' },
  'BD': { name: '追逃循环', pattern: '直接对内敛', desc: '一方越是直接追问，另一方越是退缩沉默。形成"追—逃"的恶性循环，双方都觉得自己是受害者。' },
  'BR': { name: '引导前行', pattern: '直接对克制', desc: '一方的直接推动关系前进，另一方的克制提供缓冲。如果节奏合拍，是互补的；如果错位，会变成一方推一方退。' },
  'BS': { name: '火山暗涌', pattern: '直接对压抑', desc: '一方的直接撞上另一方的压抑。表面上一方强势，实际上压抑方在默默积累，最终可能以意想不到的方式爆发。' },
  'DD': { name: '沉默对峙', pattern: '内敛对内敛', desc: '双方都不习惯直接表达，关系中充满未说出口的话。表面平静，暗流涌动，容易在沉默中渐行渐远。' },
  'DR': { name: '缓流共生', pattern: '内敛对克制', desc: '双方都偏安静，关系像一条缓流的小河。安全但缺乏活力，需要有人主动打破平静才能注入新的能量。' },
  'DS': { name: '冰封深处', pattern: '内敛对压抑', desc: '一方退缩，一方压抑，关系像冰封的湖面。看似平静，实则两颗心都在水面下独自承受。' },
  'RR': { name: '礼貌距离', pattern: '克制对克制', desc: '双方都太过克制，关系像两条平行线。礼貌但不亲密，安全但不温暖，需要有人先卸下盔甲。' },
  'RS': { name: '隐忍博弈', pattern: '克制对压抑', desc: '一方克制自己的情绪，一方压抑自己的需求。双方都在忍，但忍的方向不同，容易在某个临界点同时崩塌。' },
  'SS': { name: '窒息迷宫', pattern: '压抑对压抑', desc: '双方都习惯压抑，关系变成了一个密不透风的空间。爱还在，但谁都不知道怎么呼吸。需要一起打开一扇窗。' },
  'DB': { name: '追逃循环', pattern: '内敛对直接', desc: '同BD模式，方向相反。一方退缩一方追问，形成"逃—追"循环。' },
  'RB': { name: '引导前行', pattern: '克制对直接', desc: '同BR模式，方向相反。' },
  'SB': { name: '火山暗涌', pattern: '压抑对直接', desc: '同BS模式，方向相反。' },
  'RD': { name: '缓流共生', pattern: '克制对内敛', desc: '同DR模式，方向相反。' },
  'SD': { name: '冰封深处', pattern: '压抑对内敛', desc: '同DS模式，方向相反。' },
  'SR': { name: '隐忍博弈', pattern: '压抑对克制', desc: '同RS模式，方向相反。' },
};

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
  const secret = env.ENCRYPTION_KEY;
  if (!secret) throw new Error('ENCRYPTION_KEY not configured');
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

  const secret = env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET not configured');
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

  const secret = env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET not configured');
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
  if (!secret) throw new Error('JWT_SECRET not configured');
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
  if (!secret) throw new Error('JWT_SECRET not configured');
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

        // 尝试获取创建者 uid
        let creatorUid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) creatorUid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        const code = generateRoomCode();
        const existing = await env.DB.prepare('SELECT id FROM rooms WHERE id = ?').bind(code).first();
        if (existing) {
          return jsonResponse({ error: '房间码冲突，请重试' }, 500, origin);
        }

        await env.DB.prepare(
          'INSERT INTO rooms (id, status, a_uid, created_at, expires_at) VALUES (?, ?, ?, datetime("now"), datetime("now", "+24 hours"))'
        ).bind(code, 'waiting', creatorUid).run();
        return jsonResponse({ code, status: 'waiting' }, 200, origin);
      }

      // 加入房间
      if (path.match(/^\/api\/room\/[A-Z0-9]{6}\/join$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);
        if (room.status !== 'waiting') return jsonResponse({ error: '房间已满或已开始' }, 400, origin);

        // 尝试获取加入者 uid
        let joinerUid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) joinerUid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        await env.DB.prepare('UPDATE rooms SET status = ?, b_uid = ? WHERE id = ?').bind('ready', joinerUid, code).run();
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

      // ══════════════════════════════════════════ 双人模式重构 API（阶段六） ══════════════════════════════════════════

      // 获取18维度问卷题目
      if (path === '/api/couple/dimensions' && request.method === 'GET') {
        return jsonResponse({ dimensions: COUPLE_DIMENSIONS }, 200, origin);
      }

      // 提交18维度问卷
      if (path === '/api/couple/questionnaire' && request.method === 'POST') {
        if (!await checkRateLimitD1(env, clientIP, 'couple_submit', 5, 60000)) {
          return jsonResponse({ error: '提交过于频繁，请稍后再试' }, 429, origin);
        }
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { roomCode, role, dimensions, miraType } = body;
        const validatedRole = validateRole(role);
        if (!validatedRole) return jsonResponse({ error: '角色错误，必须为 a 或 b' }, 400, origin);
        if (!roomCode) return jsonResponse({ error: '房间码不能为空' }, 400, origin);

        const room = await env.DB.prepare('SELECT id, status, expires_at, a_uid, b_uid FROM rooms WHERE id = ?').bind(roomCode).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);
        if (room.status !== 'ready') return jsonResponse({ error: '房间状态异常' }, 400, origin);

        // 获取提交者 uid
        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        // 验证维度数据
        if (!dimensions || typeof dimensions !== 'object') {
          return jsonResponse({ error: '维度数据格式错误' }, 400, origin);
        }
        // 每个维度最多 2000 字
        const validatedDims = {};
        for (const key of Object.keys(dimensions)) {
          const val = String(dimensions[key] || '').trim();
          if (val.length > 2000) return jsonResponse({ error: `维度 ${key} 内容过长` }, 400, origin);
          validatedDims[key] = val || '无';
        }

        // 检查是否已提交
        const existing = await env.DB.prepare(
          'SELECT id, status FROM couple_questionnaires WHERE room_code = ? AND role = ?'
        ).bind(roomCode, validatedRole).first();
        if (existing && existing.status === 'completed') {
          return jsonResponse({ error: '你已经提交过了' }, 400, origin);
        }

        const dimsJson = JSON.stringify(validatedDims);

        if (existing) {
          // 更新已有记录
          await env.DB.prepare(
            'UPDATE couple_questionnaires SET dimensions_json = ?, mira_type = ?, status = ?, updated_at = datetime("now") WHERE id = ?'
          ).bind(dimsJson, miraType || '', 'completed', existing.id).run();
        } else {
          // 新建记录
          await env.DB.prepare(
            'INSERT INTO couple_questionnaires (room_code, role, user_id, mira_type, dimensions_json, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?, "completed", datetime("now"), datetime("now"))'
          ).bind(roomCode, validatedRole, uid, miraType || '', dimsJson).run();
        }

        // 异步生成单人报告
        ctx.waitUntil(generateIndividualReport(env, roomCode, validatedRole));

        // 检查对方是否也已完成
        const otherRole = validatedRole === 'a' ? 'b' : 'a';
        const partnerQ = await env.DB.prepare(
          'SELECT status FROM couple_questionnaires WHERE room_code = ? AND role = ?'
        ).bind(roomCode, otherRole).first();

        const partnerReady = !!(partnerQ && partnerQ.status === 'completed');

        return jsonResponse({
          success: true,
          individualReportReady: true,
          partnerReady,
          sharedReportReady: partnerReady,
        }, 200, origin);
      }

      // 获取单人问卷状态及报告
      if (path.match(/^\/api\/couple\/questionnaire\/[A-Z0-9]{6}\/[ab]$/) && request.method === 'GET') {
        const code = path.split('/')[4];
        const role = path.split('/')[5];

        const room = await env.DB.prepare('SELECT id, status, expires_at FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);

        const myQ = await env.DB.prepare(
          'SELECT dimensions_json, individual_report_json, status, mira_type FROM couple_questionnaires WHERE room_code = ? AND role = ?'
        ).bind(code, role).first();

        const otherRole = role === 'a' ? 'b' : 'a';
        const partnerQ = await env.DB.prepare(
          'SELECT status FROM couple_questionnaires WHERE room_code = ? AND role = ?'
        ).bind(code, otherRole).first();

        let individualReport = null;
        if (myQ && myQ.individual_report_json && myQ.individual_report_json !== '{}') {
          try { individualReport = JSON.parse(myQ.individual_report_json); } catch (e) { /* 解析失败 */ }
        }

        return jsonResponse({
          myStatus: myQ ? myQ.status : 'pending',
          myDimensions: myQ ? JSON.parse(myQ.dimensions_json || '{}') : {},
          myMiraType: myQ ? myQ.mira_type : '',
          individualReport,
          partnerCompleted: !!(partnerQ && partnerQ.status === 'completed'),
          roomStatus: room.status,
        }, 200, origin);
      }

      // 获取关系共同洞察（双方都完成后）
      if (path.match(/^\/api\/couple\/shared\/[A-Z0-9]{6}$/) && request.method === 'GET') {
        const code = path.split('/')[4];

        const room = await env.DB.prepare('SELECT id, status, expires_at, shared_report FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);

        // 检查双方是否都完成了问卷
        const qA = await env.DB.prepare(
          'SELECT dimensions_json, individual_report_json, mira_type, status FROM couple_questionnaires WHERE room_code = ? AND role = "a"'
        ).bind(code).first();
        const qB = await env.DB.prepare(
          'SELECT dimensions_json, individual_report_json, mira_type, status FROM couple_questionnaires WHERE room_code = ? AND role = "b"'
        ).bind(code).first();

        if (!qA || !qB || qA.status !== 'completed' || qB.status !== 'completed') {
          return jsonResponse({ error: '双方尚未完成问卷', ready: false }, 200, origin);
        }

        // 如果共同报告还没生成，触发生成
        let sharedReport = null;
        if (room.shared_report) {
          try { sharedReport = JSON.parse(room.shared_report); } catch (e) { /* 解析失败 */ }
        }

        if (!sharedReport) {
          // 没有共同报告时，触发或重新触发生成
          // 如果状态不是 completed，都允许触发（防止上次 ctx.waitUntil 超时后卡死）
          if (room.status !== 'completed') {
            await env.DB.prepare('UPDATE rooms SET status = "couple_analyzing" WHERE id = ?').bind(code).run();
            ctx.waitUntil(generateCoupleSharedReport(env, code));
          }
          return jsonResponse({ ready: false, message: '共同洞察正在生成中…' }, 200, origin);
        }

        // 构建交叉验证数据
        const aDims = JSON.parse(qA.dimensions_json || '{}');
        const bDims = JSON.parse(qB.dimensions_json || '{}');
        const crossValidation = buildCrossValidation(aDims, bDims);

        // 关系原型
        const archetype = getRelationshipArchetype(qA.mira_type || 'ST', qB.mira_type || 'ST');

        return jsonResponse({
          ready: true,
          sharedReport,
          archetype,
          crossValidation,
          aMiraType: qA.mira_type || '',
          bMiraType: qB.mira_type || '',
        }, 200, origin);
      }

      // 提交准确度反馈
      if (path === '/api/couple/feedback' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { roomCode, role, accuracy, feedbackText, feedbackType } = body;
        const validatedRole = validateRole(role);
        if (!validatedRole) return jsonResponse({ error: '角色错误' }, 400, origin);
        if (!roomCode) return jsonResponse({ error: '房间码不能为空' }, 400, origin);
        if (!['accurate', 'partial', 'inaccurate'].includes(accuracy)) {
          return jsonResponse({ error: '准确度选项无效' }, 400, origin);
        }

        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        // 检查是否已反馈
        const existing = await env.DB.prepare(
          'SELECT id FROM couple_feedback WHERE room_code = ? AND role = ? AND feedback_type = ?'
        ).bind(roomCode, validatedRole, feedbackType || 'shared').first();

        if (existing) {
          await env.DB.prepare(
            'UPDATE couple_feedback SET accuracy = ?, feedback_text = ? WHERE id = ?'
          ).bind(accuracy, (feedbackText || '').substring(0, 500), existing.id).run();
        } else {
          await env.DB.prepare(
            'INSERT INTO couple_feedback (room_code, role, user_id, feedback_type, accuracy, feedback_text) VALUES (?, ?, ?, ?, ?, ?)'
          ).bind(roomCode, validatedRole, uid, feedbackType || 'shared', accuracy, (feedbackText || '').substring(0, 500)).run();
        }

        return jsonResponse({ success: true }, 200, origin);
      }

      // ═══ 双人模式回溯流程 ═══

      // 提交回溯问卷（POST /api/couple/retrace）
      if (path === '/api/couple/retrace' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { roomCode, role, dimensions, miraType } = body;
        const validatedRole = validateRole(role);
        if (!validatedRole) return jsonResponse({ error: '角色错误' }, 400, origin);
        if (!roomCode) return jsonResponse({ error: '房间码不能为空' }, 400, origin);

        const room = await env.DB.prepare('SELECT id, status, expires_at, shared_report, retrace_status FROM rooms WHERE id = ?').bind(roomCode).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);
        if (!room.shared_report) return jsonResponse({ error: '共同报告尚未生成' }, 400, origin);

        // 解析共同报告获取回溯建议
        let sharedReport = null;
        try { sharedReport = JSON.parse(room.shared_report); } catch (e) { /* 解析失败 */ }
        const eventAlignment = sharedReport ? sharedReport.eventAlignment : '';
        if (!eventAlignment || eventAlignment === 'same') {
          return jsonResponse({ error: '事件一致，无需回溯' }, 400, origin);
        }

        // 验证必答题
        const dimsJson = dimensions || {};
        const requiredDims = COUPLE_DIMENSIONS.filter(d => d.required);
        for (const d of requiredDims) {
          if (!dimsJson[d.id] || !dimsJson[d.id].trim()) {
            return jsonResponse({ error: '必答题 "' + d.label + '" 未填写' }, 400, origin);
          }
        }

        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        // 存储回溯问卷
        const retraceJson = JSON.stringify({
          role: validatedRole,
          dimensions: dimsJson,
          miraType: miraType || '',
          userId: uid,
          createdAt: new Date().toISOString()
        });

        await env.DB.prepare(
          'UPDATE rooms SET retrace_questionnaire = ?, retrace_role = ?, retrace_status = "analyzing" WHERE id = ?'
        ).bind(retraceJson, validatedRole, roomCode).run();

        // 触发回溯报告生成
        ctx.waitUntil(generateRetraceReport(env, roomCode));

        return jsonResponse({ success: true, message: '回溯问卷已提交，正在生成分析报告…' }, 200, origin);
      }

      // 轮询回溯报告状态（GET /api/couple/retrace/status?code=XXX）
      if (path === '/api/couple/retrace/status' && request.method === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) return jsonResponse({ error: '缺少房间码' }, 400, origin);

        const room = await env.DB.prepare('SELECT id, status, expires_at, retrace_status, retrace_report, retrace_role, retrace_questionnaire, shared_report FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);

        let retraceReport = null;
        if (room.retrace_report) {
          try { retraceReport = JSON.parse(room.retrace_report); } catch (e) { /* 解析失败 */ }
        }

        let sharedReport = null;
        if (room.shared_report) {
          try { sharedReport = JSON.parse(room.shared_report); } catch (e) { /* 解析失败 */ }
        }

        return jsonResponse({
          retraceStatus: room.retrace_status || '',
          retraceReport,
          retraceRole: room.retrace_role || '',
          hasRetraceQuestionnaire: !!(room.retrace_questionnaire),
          eventAlignment: sharedReport ? sharedReport.eventAlignment : '',
          ready: !!(retraceReport && room.retrace_status === 'completed')
        }, 200, origin);
      }

      // 生成最终总结报告（POST /api/couple/final-report）
      if (path === '/api/couple/final-report' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { roomCode } = body;
        if (!roomCode) return jsonResponse({ error: '房间码不能为空' }, 400, origin);

        const room = await env.DB.prepare('SELECT id, status, expires_at, shared_report, retrace_report, retrace_status, final_status FROM rooms WHERE id = ?').bind(roomCode).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);
        if (!room.shared_report) return jsonResponse({ error: '共同报告尚未生成' }, 400, origin);

        // 如果已有最终报告，直接返回
        if (room.final_report && room.final_status === 'completed') {
          let finalReport = null;
          try { finalReport = JSON.parse(room.final_report); } catch (e) { /* 解析失败 */ }
          if (finalReport) {
            return jsonResponse({ success: true, finalReport, status: 'completed' }, 200, origin);
          }
        }

        // 触发最终报告生成
        await env.DB.prepare('UPDATE rooms SET final_status = "analyzing" WHERE id = ?').bind(roomCode).run();
        ctx.waitUntil(generateFinalSummaryReport(env, roomCode));

        return jsonResponse({ success: true, message: '最终总结报告正在生成中…' }, 200, origin);
      }

      // 轮询最终报告状态（GET /api/couple/final-report/status?code=XXX）
      if (path === '/api/couple/final-report/status' && request.method === 'GET') {
        const code = url.searchParams.get('code');
        if (!code) return jsonResponse({ error: '缺少房间码' }, 400, origin);

        const room = await env.DB.prepare('SELECT id, expires_at, final_status, final_report FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404, origin);
        if (isExpired(room)) return jsonResponse({ error: '房间已过期' }, 410, origin);

        let finalReport = null;
        if (room.final_report) {
          try { finalReport = JSON.parse(room.final_report); } catch (e) { /* 解析失败 */ }
        }

        return jsonResponse({
          finalStatus: room.final_status || '',
          finalReport,
          ready: !!(finalReport && room.final_status === 'completed')
        }, 200, origin);
      }

      // 提交评分（POST /api/couple/scoring）
      if (path === '/api/couple/scoring' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { roomCode, role, accuracy, helpfulness, feedback, reportType } = body;
        const validatedRole = validateRole(role);
        if (!validatedRole) return jsonResponse({ error: '角色错误' }, 400, origin);
        if (!roomCode) return jsonResponse({ error: '房间码不能为空' }, 400, origin);
        if (!['accurate', 'partial', 'inaccurate'].includes(accuracy)) {
          return jsonResponse({ error: '准确度选项无效' }, 400, origin);
        }
        const helpfulnessScore = parseInt(helpfulness) || 0;
        if (helpfulnessScore < 0 || helpfulnessScore > 5) {
          return jsonResponse({ error: '有帮助程度分数无效（0-5）' }, 400, origin);
        }

        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        const rptType = reportType || 'final';

        // 检查是否已评分
        const existing = await env.DB.prepare(
          'SELECT id FROM couple_feedback WHERE room_code = ? AND role = ? AND feedback_type = ? AND report_type = ?'
        ).bind(roomCode, validatedRole, 'scoring', rptType).first();

        if (existing) {
          await env.DB.prepare(
            'UPDATE couple_feedback SET accuracy = ?, helpfulness = ?, feedback_text = ? WHERE id = ?'
          ).bind(accuracy, helpfulnessScore, (feedback || '').substring(0, 500), existing.id).run();
        } else {
          await env.DB.prepare(
            'INSERT INTO couple_feedback (room_code, role, user_id, feedback_type, accuracy, helpfulness, feedback_text, report_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
          ).bind(roomCode, validatedRole, uid, 'scoring', accuracy, helpfulnessScore, (feedback || '').substring(0, 500), rptType).run();
        }

        // 同时记录到 analysis_history（成长板块）
        if (uid) {
          try {
            const room = await env.DB.prepare('SELECT shared_report, retrace_report, final_report FROM rooms WHERE id = ?').bind(roomCode).first();
            const reportSummary = room.final_report || room.retrace_report || room.shared_report || '{}';
            let summaryText = '';
            try {
              const rpt = JSON.parse(reportSummary);
              summaryText = rpt.eventAnalysis || rpt.commonNeed || rpt.interactionPattern || '双人模式分析';
            } catch (e) { summaryText = '双人模式分析'; }

            await env.DB.prepare(
              'INSERT INTO analysis_history (user_id, source_type, source_id, mira_type, dimensions_json, insight_summary) VALUES (?, "couple_scoring", NULL, "", ?, ?)'
            ).bind(uid, reportSummary.substring(0, 10000), (accuracy + '|' + helpfulnessScore + '|' + (feedback || '')).substring(0, 500)).run();
          } catch (e) {
            console.error('记录到成长板块失败:', e.message);
          }
        }

        return jsonResponse({ success: true }, 200, origin);
      }
      if (path === '/api/mira-accuracy-feedback' && request.method === 'POST') {
        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { inferredType, testType, vote, source } = body;
        if (!inferredType || !testType || !vote) {
          return jsonResponse({ error: '缺少必要参数' }, 400, origin);
        }
        if (!['inferred', 'test', 'both'].includes(vote)) {
          return jsonResponse({ error: '投票选项无效' }, 400, origin);
        }

        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        // 确保表存在（自动创建）
        try {
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS mira_accuracy_feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id INTEGER,
              inferred_type TEXT,
              test_type TEXT,
              vote TEXT,
              source TEXT DEFAULT 'analysis_compare',
              created_at TEXT DEFAULT (datetime('now'))
            )
          `).run();
        } catch (tableErr) { /* 表可能已存在 */ }

        await env.DB.prepare(
          'INSERT INTO mira_accuracy_feedback (user_id, inferred_type, test_type, vote, source) VALUES (?, ?, ?, ?, ?)'
        ).bind(uid, inferredType, testType, vote, source || 'analysis_compare').run();

        return jsonResponse({ success: true }, 200, origin);
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

        const { prompt, mode, history, userInput } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 10000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        // 尝试从请求头拿 uid（无 token 则 uid=null，兼容游客）
        let uid = null;
        try {
          const auth = await getAuthUser(request, env);
          if (!auth.error && auth.uid) uid = auth.uid;
        } catch (e) { /* 游客模式 */ }

        let result;
        try {
          result = await callAI(env, prompt, mode || 'single', history || []);
        } catch (e) {
          return jsonResponse({ error: 'callAI 异常: ' + e.message }, 500, origin);
        }

        // 保存分析结果时，使用用户实际输入而非 AI 指令
        const saveInput = userInput || prompt;
        if (!result.error && (mode || 'single') === 'single') {
          ctx.waitUntil(saveSingleAnalysis(env, saveInput, result, uid));
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
            } else if (currentNode.condition_type === 'has_misread') {
              nextNodeId = signals.hasMisread ? currentNode.next_node_sufficient : currentNode.next_node_insufficient;
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

            const result = await callAI(env, prompt, 'chat', history || [], nodePrompt, currentRound);

            // 决策树完全控制流程：action 由 nodeType 决定，不依赖 AI 返回
            const treeAction = currentNode.node_type === 'offer_analyze' ? 'offer_analyze'
              : currentNode.node_type === 'analyze' ? 'analyze'
              : 'ask';

            return jsonResponse({
              reply: result.reply || result.raw || '',
              action: treeAction,
              followUp: result.followUp || [],
              attachment: result.attachment || { emotion: '', dimension: '', sufficientSignals: signals, round: currentRound },
              currentNodeId: nextNodeId,
              nodeType: currentNode.node_type,
            }, result.error ? 500 : 200, origin);
          }
        }

        // 回退到旧逻辑
        const result = await callAI(env, prompt, 'chat', history || [], null, round || 1);
        return jsonResponse(result, result.error ? 500 : 200, origin);
      }

      // ══════════════════════════════════════════ 数据库初始化 API ══════════════════════════════════════════

      // 初始化数据库表（GET /api/init-db）
      if (path === '/api/init-db' && request.method === 'GET') {
        const auth = await checkAdminAuth(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
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

          // 双人模式回溯流程字段
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN retrace_role TEXT DEFAULT ""').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN retrace_questionnaire TEXT DEFAULT ""').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN retrace_report TEXT DEFAULT ""').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN retrace_status TEXT DEFAULT ""').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN final_report TEXT DEFAULT ""').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE rooms ADD COLUMN final_status TEXT DEFAULT ""').run(); } catch(e) { /* 已存在 */ }

          // 评分表扩展字段
          try { await env.DB.prepare('ALTER TABLE couple_feedback ADD COLUMN helpfulness INTEGER DEFAULT 0').run(); } catch(e) { /* 已存在 */ }
          try { await env.DB.prepare('ALTER TABLE couple_feedback ADD COLUMN report_type TEXT DEFAULT "shared"').run(); } catch(e) { /* 已存在 */ }

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

          // 决策树种子数据 v2（4维度×多轮追问+循环结构）
          // 维度顺序：事实→情绪→需求→误读，每维度最多追问2轮
          const treeCount = await env.DB.prepare('SELECT COUNT(*) as cnt FROM chat_decision_tree').first();
          const treeNeedsMigration = !treeCount || treeCount.cnt === 0 || treeCount.cnt <= 11; // 旧版最多11个节点
          if (treeNeedsMigration) {
            // 清空旧决策树数据
            try { await env.DB.prepare('DELETE FROM chat_decision_tree').run(); } catch(e) {}
            const seedNodes = [
              // ── 起始 ──
              ['start', null, 'collect', '', '', '用户刚开口说了：{userInput}。请用1句话承接情绪（引用用户原话关键词），然后基于依恋理论判断最该追问的方向。回复2-4句话。', 'assess_fact', null, '起始：承接情绪+判断方向', 1, 0],

              // ── 事实维度（最多2轮追问）──
              ['assess_fact', 'start', 'ask', 'has_fact', '', '评估用户是否提供了具体事实（发生了什么、什么时候、具体情境）。如果已有具体事件描述，进入情绪维度；如果缺少，追问事实。', 'assess_emotion', 'ask_fact_1', '评估事实维度', 1, 1],
              ['ask_fact_1', 'assess_fact', 'ask', '', '', '用户缺少具体事实。请温和追问一个事实性问题，如"能给我举个例子吗？""具体是哪一次？"不要一次问多个问题。回复2-3句话。', 'assess_fact_2', null, '追问事实第1轮', 1, 2],
              ['assess_fact_2', 'ask_fact_1', 'ask', 'has_fact', '', '再次评估事实维度是否充足。', 'assess_emotion', 'ask_fact_2', '评估事实维度（第2次）', 1, 3],
              ['ask_fact_2', 'assess_fact_2', 'ask', '', '', '事实仍不够具体。再追问一次，换一种问法，如"那件事发生的场景是什么样的？""当时你们各自在做什么？"回复2-3句话。', 'assess_emotion', null, '追问事实第2轮（最后一轮）', 1, 4],

              // ── 情绪维度（最多2轮追问）──
              ['assess_emotion', 'assess_fact', 'ask', 'has_emotion', '', '评估用户是否表达了情绪感受（当下的感觉、身体反应、情绪词）。如果已有，进入需求维度；如果缺少，追问情绪。', 'assess_need', 'ask_emotion_1', '评估情绪维度', 1, 5],
              ['ask_emotion_1', 'assess_emotion', 'ask', '', '', '用户缺少情绪表达。请引导感受层，如"那时候你心里是什么感觉？""你身体有什么反应？"回复2-3句话。', 'assess_emotion_2', null, '追问情绪第1轮', 1, 6],
              ['assess_emotion_2', 'ask_emotion_1', 'ask', 'has_emotion', '', '再次评估情绪维度是否充足。', 'assess_need', 'ask_emotion_2', '评估情绪维度（第2次）', 1, 7],
              ['ask_emotion_2', 'assess_emotion_2', 'ask', '', '', '情绪仍不够清晰。再引导一次，如"如果把那种感觉比作一种天气，会是什么？""你说还好，但听起来好像有点委屈？"回复2-3句话。', 'assess_need', null, '追问情绪第2轮（最后一轮）', 1, 8],

              // ── 需求维度（最多2轮追问）──
              ['assess_need', 'assess_emotion', 'ask', 'has_need', '', '评估用户是否表达了核心需求（真正想要什么、希望对方怎么做）。如果已有，进入误读维度；如果缺少，追问需求。', 'assess_misread', 'ask_need_1', '评估需求维度', 1, 9],
              ['ask_need_1', 'assess_need', 'ask', '', '', '用户缺少需求表达。请引导需求层，如"你真正想要的是什么？""你最希望TA能给你什么？"回复2-3句话。', 'assess_need_2', null, '追问需求第1轮', 1, 10],
              ['assess_need_2', 'ask_need_1', 'ask', 'has_need', '', '再次评估需求维度是否充足。', 'assess_misread', 'ask_need_2', '评估需求维度（第2次）', 1, 11],
              ['ask_need_2', 'assess_need_2', 'ask', '', '', '需求仍不够明确。再引导一次，如"如果TA能做一件事让你安心，你希望是什么？""你刚才说的那些，背后最在意的到底是什么？"回复2-3句话。', 'assess_misread', null, '追问需求第2轮（最后一轮）', 1, 12],

              // ── 误读维度（最多2轮追问）──
              ['assess_misread', 'assess_need', 'ask', 'has_misread', '', '评估用户是否透露了对对方意图的解读（"TA肯定是觉得…""TA就是不在乎我"）。如果有，进入出报告阶段；如果缺少，引导误读。', 'offer_analyze', 'ask_misread_1', '评估误读维度', 1, 13],
              ['ask_misread_1', 'assess_misread', 'ask', '', '', '用户没有透露对对方意图的解读。请引导，如"你觉得TA当时那么做，是什么意思？""在你看来，TA为什么会那样反应？"回复2-3句话。', 'assess_misread_2', null, '追问误读第1轮', 1, 14],
              ['assess_misread_2', 'ask_misread_1', 'ask', 'has_misread', '', '再次评估误读维度是否充足。', 'offer_analyze', 'ask_misread_2', '评估误读维度（第2次）', 1, 15],
              ['ask_misread_2', 'assess_misread_2', 'ask', '', '', '误读仍不够明确。再引导一次，如"如果你站在TA的角度，你觉得TA当时在想什么？""你觉得你们之间最大的误解可能在哪里？"回复2-3句话。', 'offer_analyze', null, '追问误读第2轮（最后一轮）', 1, 16],

              // ── 出报告/继续对话 ──
              ['offer_analyze', 'assess_misread', 'offer_analyze', '', '', '四个维度的信息已经收集得差不多了。请用温暖的方式告诉用户：聊了这么多，信息看起来够了，接下来怎么走交给你。不要用问句，下方会有按钮让用户选择。', 'analyze', 'continue_chat', '信息充足，给用户选择', 1, 17],
              ['continue_chat', 'offer_analyze', 'ask', 'round_count', '>=50', '已达50轮软上限，请温和地告诉用户：聊了这么多，我来帮你梳理一下吧。', 'analyze', 'continue_chat', '继续对话（50轮后强制分析）', 1, 18],
              ['analyze', 'offer_analyze', 'analyze', '', '', '用户选择生成报告。请告诉用户：好的，我来帮你梳理一下。', 'end', null, '生成分析报告', 1, 19],
              ['end', 'analyze', 'end', '', '', '分析已完成。', null, null, '结束节点', 1, 20],
            ];
            for (const node of seedNodes) {
              await env.DB.prepare(
                'INSERT OR IGNORE INTO chat_decision_tree (node_id, parent_id, node_type, condition_type, condition_value, prompt_template, next_node_sufficient, next_node_insufficient, description, is_active, sort_order) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
              ).bind(...node).run();
            }
          }

          // ═══ 阶段六：双人模式重构 — 18维度问卷 + 准确度反馈 ═══

          // 双人模式18维度问卷表
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS couple_questionnaires (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              room_code TEXT NOT NULL,
              role TEXT NOT NULL,
              user_id INTEGER,
              mira_type TEXT DEFAULT '',
              dimensions_json TEXT DEFAULT '{}',
              individual_report_json TEXT DEFAULT '{}',
              status TEXT DEFAULT 'pending',
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
              updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_couple_q_room ON couple_questionnaires(room_code, role)').run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_couple_q_user ON couple_questionnaires(user_id, created_at)').run();

          // 准确度反馈表
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS couple_feedback (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              room_code TEXT NOT NULL,
              role TEXT NOT NULL,
              user_id INTEGER,
              feedback_type TEXT DEFAULT 'shared',
              accuracy TEXT DEFAULT '',
              feedback_text TEXT DEFAULT '',
              created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_couple_fb_room ON couple_feedback(room_code, role)').run();

          // schema_version 版本管理表
          await env.DB.prepare(`
            CREATE TABLE IF NOT EXISTS schema_version (
              version INTEGER PRIMARY KEY,
              description TEXT,
              applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
          `).run();
          try {
            await env.DB.prepare('INSERT OR IGNORE INTO schema_version (version, description) VALUES (?, ?)').bind(3, 'v3: couple_questionnaires, couple_feedback (双人模式重构)').run();
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
          user_input: base64Decode(row.user_input),
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

      // ══════════════════════════════════════════ 数据主权 API（阶段七） ══════════════════════════════════════════

      // 导出双人数据（GET /api/user/couple/export）
      if (path === '/api/user/couple/export' && request.method === 'GET') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);

        // 获取所有双人房间记录
        const rooms = await env.DB.prepare(
          'SELECT id, room_code, role, my_mira_type, partner_mira_type, shared_report_json, my_insight_json, partner_insight_json, created_at FROM user_room_records WHERE user_id = ? ORDER BY created_at DESC'
        ).bind(auth.uid).all();

        // 获取所有双人问卷数据
        const questionnaires = await env.DB.prepare(
          'SELECT id, room_code, role, mira_type, dimensions_json, individual_report_json, status, created_at FROM couple_questionnaires WHERE user_id = ? ORDER BY created_at DESC'
        ).bind(auth.uid).all();

        // 获取所有反馈
        const feedbacks = await env.DB.prepare(
          'SELECT id, room_code, role, feedback_type, accuracy, feedback_text, created_at FROM couple_feedback WHERE user_id = ? ORDER BY created_at DESC'
        ).bind(auth.uid).all();

        const exportData = {
          exportTime: new Date().toISOString(),
          userId: auth.uid,
          coupleRooms: (rooms.results || []).map(r => {
            let shared = null, myInsight = null, partnerInsight = null;
            try { shared = r.shared_report_json ? JSON.parse(r.shared_report_json) : null; } catch (e) {}
            try { myInsight = r.my_insight_json ? JSON.parse(r.my_insight_json) : null; } catch (e) {}
            try { partnerInsight = r.partner_insight_json ? JSON.parse(r.partner_insight_json) : null; } catch (e) {}
            return {
              id: r.id,
              roomCode: r.room_code,
              role: r.role,
              myMiraType: r.my_mira_type,
              partnerMiraType: r.partner_mira_type,
              sharedReport: shared,
              myInsight,
              partnerInsight,
              createdAt: r.created_at,
            };
          }),
          questionnaires: (questionnaires.results || []).map(q => {
            let dims = null, report = null;
            try { dims = q.dimensions_json ? JSON.parse(q.dimensions_json) : null; } catch (e) {}
            try { report = q.individual_report_json ? JSON.parse(q.individual_report_json) : null; } catch (e) {}
            return {
              id: q.id,
              roomCode: q.room_code,
              role: q.role,
              miraType: q.mira_type,
              dimensions: dims,
              individualReport: report,
              status: q.status,
              createdAt: q.created_at,
            };
          }),
          feedbacks: feedbacks.results || [],
        };

        return jsonResponse(exportData, 200, origin);
      }

      // 删除双人房间记录（DELETE /api/user/rooms/:id）
      if (path.match(/^\/api\/user\/rooms\/\d+\/delete$/) && request.method === 'POST') {
        const auth = await getAuthUser(request, env);
        if (auth.error) return jsonResponse({ error: auth.error }, 401, origin);
        const id = parseInt(path.split('/')[4], 10);
        if (!id) return jsonResponse({ error: '无效的记录ID' }, 400, origin);

        // 验证记录归属
        const row = await env.DB.prepare('SELECT id, room_code FROM user_room_records WHERE id = ? AND user_id = ?').bind(id, auth.uid).first();
        if (!row) return jsonResponse({ error: '记录不存在' }, 404, origin);

        // 删除房间记录
        await env.DB.prepare('DELETE FROM user_room_records WHERE id = ? AND user_id = ?').bind(id, auth.uid).run();

        // 删除关联的问卷数据
        try { await env.DB.prepare('DELETE FROM couple_questionnaires WHERE room_code = ? AND user_id = ?').bind(row.room_code, auth.uid).run(); } catch (e) {}

        // 删除关联的反馈
        try { await env.DB.prepare('DELETE FROM couple_feedback WHERE room_code = ? AND user_id = ?').bind(row.room_code, auth.uid).run(); } catch (e) {}

        await logSecurityEvent(env, 'data_deletion', { type: 'couple_room', id, roomCode: row.room_code }, clientIP, path, auth.uid, null);

        return jsonResponse({ success: true, message: '双人数据已删除' }, 200, origin);
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
async function callAI(env, prompt, mode, history, systemPromptOverride, round) {
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
2. 再根据【当前阶段任务】的指引决定追问方向
3. 每轮回复控制在 2-4 句话，不超过 80 字。不要长篇大论。

信息充足评估标准（你需要评估以下4个信号）：
- hasFact（事实）：用户是否提供了具体事件描述（发生了什么、什么时候、具体情境）
- hasEmotion（情绪）：用户是否表达了情绪感受（当下的感觉、身体反应、情绪词）
- hasNeed（需求）：用户是否表达了核心需求（真正想要什么、希望对方怎么做）
- hasMisread（误读）：用户是否透露了对对方意图的解读（"TA肯定是觉得…""TA就是不在乎我"）

误读维度的评估要点：
- 用户说的"TA怎么怎么样"都是用户的主观解读，不是客观事实
- 你要识别用户对对方意图的归因方式（恶意归因 vs 善意归因）
- 在回复中可以温和地提供另一种视角，但不要说教

处理敷衍/恶意输入：
- 如果用户回答很敷衍（只回"嗯""还好""不知道"），尝试换一种问法，给具体方向引导
- 如果用户明显恶意（无意义文字、辱骂、挑衅），礼貌拒绝："Mirror 是帮助理解关系困惑的。如果你愿意说说发生了什么，我会认真听。"

绝对限制：
- 禁止心理诊断、人格标签化结论
- 禁止 PUA、操控、冷暴力、断联套路建议
- 禁止把推测写成事实
- 如果出现家暴、自伤、自杀等高风险内容，立即停止常规对话，优先确认安全

输出格式（严格 JSON，不要 Markdown 代码块，不要额外说明文字）：
{"reply":"你对用户说的自然语言回复（2-4句话，先承接情绪再追问）","followUp":["1-2个追问问题"],"attachment":{"emotion":"识别到的核心情绪","dimension":"fact|emotion|need|misread","sufficientSignals":{"hasFact":false,"hasEmotion":false,"hasNeed":false,"hasMisread":false},"round":1}}

注意：你不需要决定何时出报告，流程推进由决策树控制。你只需关注当前阶段的追问任务，并诚实评估4个信号。`,
    quote: '你是一位有洞察力的文案专家。请直接输出一句金句（20-40字），像朋友说的心里话，带一点自嘲或反差。只输出金句本身，不要引号不要解释。',
  };

  const basePrompt = systemPrompts[mode] || systemPrompts.single;
  const systemPrompt = systemPromptOverride ? basePrompt + '\n\n【当前阶段任务】' + systemPromptOverride : basePrompt;

  // Anthropic 格式：system 单独字段，messages 只含 user/assistant
  const messages = [
    ...(history || []),
    { role: 'user', content: prompt },
  ];

  const maxRetries = 2;
  const timeoutMs = 30000;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    let response;
    try {
      response = await fetchWithTimeout('https://api.deepseek.com/anthropic/v1/messages', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': env.AI_API_KEY,
          'anthropic-version': '2023-06-01',
        },
        body: JSON.stringify({
          model: 'deepseek-v4-flash',
          messages,
          max_tokens: 2000,
          system: systemPrompt,
          thinking: { type: 'disabled' },
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

    // 对 401/502/503/504/429 错误进行重试
    if (!response.ok) {
      const status = response.status;
      if ((status === 401 || status === 502 || status === 503 || status === 504 || status === 429) && attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      return { error: `AI 服务返回错误 (${status})`, raw: null };
    }

    try {
      const data = await response.json();
      // Anthropic 格式：content 是数组，提取 type="text" 的 text 字段
      let content = '';
      if (data.content && Array.isArray(data.content)) {
        for (const block of data.content) {
          if (block.type === 'text' && block.text) {
            content += block.text;
          }
        }
      }

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

      // chat 模式：JSON 解析失败时，根据轮数智能判断下一步
      if (mode === 'chat') {
        const r = round || 1;
        if (r >= 50) {
          // 达到硬上限，强制出报告
          return {
            reply: '聊了这么多，我来帮你梳理一下。',
            action: 'analyze',
            followUp: [],
            attachment: { emotion: '', dimension: '', sufficientSignals: { hasFact: true, hasEmotion: true, hasNeed: true }, round: r }
          };
        } else if (r >= 3) {
          // 超过3轮且AI返回非JSON，给用户选择权
          return {
            reply: '能这样清晰地看见自己的变化，真的不容易。聊了这么多，信息差不多了，接下来怎么走交给你。',
            action: 'offer_analyze',
            followUp: [],
            attachment: { emotion: '', dimension: '', sufficientSignals: { hasFact: true, hasEmotion: true, hasNeed: true }, round: r }
          };
        }
        // 3轮以内，继续追问
        return {
          reply: content,
          action: 'ask',
          followUp: [],
          attachment: { emotion: '', dimension: '', sufficientSignals: { hasFact: false, hasEmotion: false, hasNeed: false }, round: r }
        };
      }

      return { raw: content, error: 'JSON解析失败' };
    } catch (parseErr) {
      if (attempt < maxRetries) {
        await new Promise(r => setTimeout(r, 1500 * (attempt + 1)));
        continue;
      }
      return { error: 'AI 响应格式异常，请稍后重试', raw: null };
    }
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

// ══════════════════════════════════════════ 双人模式重构 — 核心函数 ══════════════════════════════════════════

// 关系原型规则引擎：根据双方MIRA类型推导核心互动结构
function getRelationshipArchetype(aMiraType, bMiraType) {
  const aExpr = (aMiraType || 'S').charAt(0).toUpperCase();
  const bExpr = (bMiraType || 'S').charAt(0).toUpperCase();
  const key = aExpr + bExpr;
  const archetype = RELATIONSHIP_ARCHETYPES[key] || RELATIONSHIP_ARCHETYPES['SS'];
  return {
    key,
    name: archetype.name,
    pattern: archetype.pattern,
    desc: archetype.desc,
    aExpression: aExpr,
    bExpression: bExpr,
  };
}

// 构建交叉验证数据：对比"你以为TA的意思" vs "TA实际表达的"
function buildCrossValidation(aDims, bDims) {
  // A对B的解读 vs B的实际表达
  const aMisreadOfB = {
    label: 'A以为B的意思',
    interpretation: aDims.d13 || '无',  // A觉得B是什么意思
    reason: aDims.d14 || '无',          // A猜测B为什么这样
    biggestGap: aDims.d15 || '无',      // A觉得最大误解在哪
  };
  const bActualExpression = {
    label: 'B实际表达的',
    fact: bDims.d1 || '无',              // B描述的事实
    context: bDims.d2 || '无',           // B描述的情境
    process: bDims.d4 || '无',           // B描述的经过
  };

  // B对A的解读 vs A的实际表达
  const bMisreadOfA = {
    label: 'B以为A的意思',
    interpretation: bDims.d13 || '无',
    reason: bDims.d14 || '无',
    biggestGap: bDims.d15 || '无',
  };
  const aActualExpression = {
    label: 'A实际表达的',
    fact: aDims.d1 || '无',
    context: aDims.d2 || '无',
    process: aDims.d4 || '无',
  };

  return {
    aViewsB: { misread: aMisreadOfB, actual: bActualExpression },
    bViewsA: { misread: bMisreadOfA, actual: aActualExpression },
  };
}

// 生成单人报告（基于18维度问卷数据）
async function generateIndividualReport(env, roomCode, role) {
  try {
    const q = await env.DB.prepare(
      'SELECT dimensions_json, mira_type, user_id FROM couple_questionnaires WHERE room_code = ? AND role = ?'
    ).bind(roomCode, role).first();
    if (!q || !q.dimensions_json) {
      console.error('generateIndividualReport: questionnaire not found', roomCode, role);
      return;
    }

    const dims = JSON.parse(q.dimensions_json || '{}');

    // 构建AI提示词
    const dimText = COUPLE_DIMENSIONS.map(d => {
      const answer = dims[d.id] || '无';
      return `【${d.label}】\n${answer}`;
    }).join('\n\n');

    const prompt = `你是一位关系咨询师，基于依恋理论和非暴力沟通框架，分析以下用户的18维度关系问卷回答。

用户的MIRA人格类型：${q.mira_type || '未知'}

用户回答：
${dimText}

请生成单人分析报告，严格以JSON格式回复（不要包含任何其他文字），包含以下字段：
- fact: 事实摘要，客观描述用户面临的关系困境（1-2句话）
- emotion: 情绪识别，指出用户的核心情绪和深层感受（1-2句话）
- need: 核心需求，用户真正想要的是什么（1-2句话）
- misread: 可能的误读，用户对对方的解读中可能存在哪些偏差（1-2句话）
- innerThought: 用户内心真实想法，可能自己都没意识到的（1-2句话）
- translatedExpression: 用非暴力沟通的方式重新表达用户的核心诉求（1-2句话）
- insight: 深度洞察，站在客观中立视角指出关键问题（2-3句话）
- suggest: 具体可执行的改善建议（2-3条）
- miraType: 直接使用用户提供的MIRA类型 "${q.mira_type || '未知'}"`;

    const result = await callAI(env, prompt, 'single', []);

    if (result.error) {
      console.error('generateIndividualReport AI error:', result.error);
      // 存储错误状态
      await env.DB.prepare(
        'UPDATE couple_questionnaires SET individual_report_json = ?, updated_at = datetime("now") WHERE room_code = ? AND role = ?'
      ).bind(JSON.stringify({ error: '报告生成失败，请稍后重试' }), roomCode, role).run();
      return;
    }

    // 确保miraType透传
    if (!result.miraType) result.miraType = q.mira_type || '';
    result.dimensions = dims;

    const reportJson = JSON.stringify(result);
    await env.DB.prepare(
      'UPDATE couple_questionnaires SET individual_report_json = ?, updated_at = datetime("now") WHERE room_code = ? AND role = ?'
    ).bind(reportJson, roomCode, role).run();

    // 写入洞察日记
    if (q.user_id && result.insight) {
      try {
        await env.DB.prepare(
          'INSERT INTO insight_diaries (user_id, source_type, source_id, diary_text, emotion_tag, growth_tag, created_at) VALUES (?, "couple_individual", NULL, ?, ?, ?, datetime("now"))'
        ).bind(
          q.user_id,
          (result.insight || '').substring(0, 500),
          (result.emotion || '').substring(0, 50),
          '关系觉察',
        ).run();
      } catch (e) { console.error('couple insight_diary insert error:', e.message); }
    }

    // 检查对方是否也完成了，如果是则触发共同报告
    const otherRole = role === 'a' ? 'b' : 'a';
    const partnerQ = await env.DB.prepare(
      'SELECT status FROM couple_questionnaires WHERE room_code = ? AND role = ?'
    ).bind(roomCode, otherRole).first();

    if (partnerQ && partnerQ.status === 'completed') {
      // 双方都完成了，触发共同报告生成
      const room = await env.DB.prepare('SELECT status FROM rooms WHERE id = ?').bind(roomCode).first();
      if (room && room.status !== 'couple_analyzing' && room.status !== 'completed') {
        await env.DB.prepare('UPDATE rooms SET status = "couple_analyzing" WHERE id = ?').bind(roomCode).run();
        // 使用 ctx.waitUntil 的替代方案 — 直接调用（在异步上下文中）
        generateCoupleSharedReport(env, roomCode).catch(e => console.error('auto trigger shared report:', e.message));
      }
    }
  } catch (err) {
    console.error('generateIndividualReport error:', err.message);
  }
}

// 生成双人共同洞察报告（含交叉验证）
async function generateCoupleSharedReport(env, code) {
  try {
    const qA = await env.DB.prepare(
      'SELECT dimensions_json, individual_report_json, mira_type, user_id FROM couple_questionnaires WHERE room_code = ? AND role = "a"'
    ).bind(code).first();
    const qB = await env.DB.prepare(
      'SELECT dimensions_json, individual_report_json, mira_type, user_id FROM couple_questionnaires WHERE room_code = ? AND role = "b"'
    ).bind(code).first();

    if (!qA || !qB) {
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ?").bind(code).run();
      return;
    }

    const aDims = JSON.parse(qA.dimensions_json || '{}');
    const bDims = JSON.parse(qB.dimensions_json || '{}');
    const aReport = JSON.parse(qA.individual_report_json || '{}');
    const bReport = JSON.parse(qB.individual_report_json || '{}');

    // 构建交叉验证数据
    const crossValidation = buildCrossValidation(aDims, bDims);
    const archetype = getRelationshipArchetype(qA.mira_type || 'ST', qB.mira_type || 'ST');

    // 构建AI提示词
    const prompt = `你是Mirror的双人关系分析模块，基于依恋理论和非暴力沟通框架，分析两个人的关系问卷回答，生成共同洞察报告。

【关系原型】${archetype.name}（${archetype.pattern}）
${archetype.desc}

【A的MIRA类型】${qA.mira_type || '未知'}
【A的核心信息】
- 事实：${aReport.fact || aDims.d1 || '未知'}
- 情绪：${aReport.emotion || aDims.d5 || '未知'}
- 需求：${aReport.need || aDims.d9 || '未知'}
- 误读：${aReport.misread || aDims.d13 || '未知'}
- A对B的解读：${aDims.d13 || '无'}（A以为B是这个意思）
- A觉得最大误解：${aDims.d15 || '无'}

【B的MIRA类型】${qB.mira_type || '未知'}
【B的核心信息】
- 事实：${bReport.fact || bDims.d1 || '未知'}
- 情绪：${bReport.emotion || bDims.d5 || '未知'}
- 需求：${bReport.need || bDims.d9 || '未知'}
- 误读：${bReport.misread || bDims.d13 || '未知'}
- B对A的解读：${bDims.d13 || '无'}（B以为A是这个意思）
- B觉得最大误解：${bDims.d15 || '无'}

【交叉验证关键点】
- A以为B的意思："${aDims.d13 || '无'}" → B实际想表达的："${bDims.d9 || bDims.d10 || '无'}"
- B以为A的意思："${bDims.d13 || '无'}" → A实际想表达的："${aDims.d9 || aDims.d10 || '无'}"

重要判断：请先判断A和B描述的是否是同一件事。
- same: 明显是同一件事的不同视角
- related: 不是同一件事但有关联（比如同一种反复出现的模式）
- different: 完全不同的两件事

请生成共同报告，严格以JSON格式回复（不要包含任何其他文字），包含以下字段：
- eventAlignment: "same"或"related"或"different"，判断双方事件是否一致
- eventAnalysis: 对A和B描述的事件对比分析（2-3句话），指出是同一件事还是不同的事
- commonalities: 对象，包含五个维度的共同点分析：
  - fact: 两人在事实层面是否有相似之处（1句话，无则填"无共同点"）
  - emotion: 两人在情绪模式上的共通点（1句话，无则填"无共同点"）
  - need: 两人在需求层面的共通点（1句话，无则填"无共同点"）
  - misread: 两人在误读模式上的共通点（1句话，无则填"无共同点"）
  - suggest: 两人在行动意愿上的共通点（1句话，无则填"无共同点"）
- commonNeed: 两人共同的核心需求（1-2句话）
- commonMisread: 两人共同的误读模式，指出双方都在哪里误解了对方（2-3句话）
- crossValidation: 对象，包含 aMisread（A对B的误读，1句话）和 bMisread（B对A的误读，1句话）和 aActualIntent（A的真实意图，1句话）和 bActualIntent（B的真实意图，1句话）
- interactionPattern: 基于关系原型"${archetype.name}"的互动模式分析（2-3句话）
- growthDirection: 两个人可以一起成长的方向（2-3句话）
- actionableSteps: 数组，2-3条具体可执行的建议
- retraceSuggestion: 如果eventAlignment不是"same"，给出回溯建议——从哪个角色的事件切入回溯（"a"或"b"），以及理由（2-3句话）。如果eventAlignment是"same"则填空字符串""
- archetypeName: "${archetype.name}"
- archetypeDesc: "${archetype.desc}"
- aMiraType: "${qA.mira_type || ''}"
- bMiraType: "${qB.mira_type || ''}"`;

    const result = await callAI(env, prompt, 'couple', []);

    if (result.error) {
      console.error('generateCoupleSharedReport AI error:', result.error);
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ?").bind(code).run();
      return;
    }

    // 补充规则引擎数据
    result.archetype = archetype;
    result.crossValidationData = crossValidation;

    const sharedJson = JSON.stringify(result);
    await env.DB.prepare(
      'UPDATE rooms SET shared_report = ?, status = "completed" WHERE id = ?'
    ).bind(sharedJson, code).run();

    // 复制到双方 user_room_records
    try {
      await copyCoupleRoomToUserRecords(env, code, qA, qB, result);
    } catch (copyErr) {
      console.error('copyCoupleRoomToUserRecords error:', copyErr.message);
    }
  } catch (err) {
    console.error('generateCoupleSharedReport error:', err.message);
    await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'couple_analyzing'").bind(code).run();
  }
}

// ═══ 回溯报告生成 ═══
async function generateRetraceReport(env, code) {
  try {
    const room = await env.DB.prepare(
      'SELECT id, shared_report, retrace_questionnaire, retrace_role FROM rooms WHERE id = ?'
    ).bind(code).first();
    if (!room || !room.retrace_questionnaire) {
      console.error('generateRetraceReport: no retrace questionnaire');
      return;
    }

    // 解析数据
    let sharedReport = null;
    try { sharedReport = JSON.parse(room.shared_report); } catch (e) { /* 解析失败 */ }
    if (!sharedReport) {
      console.error('generateRetraceReport: no shared report');
      await env.DB.prepare('UPDATE rooms SET retrace_status = "error" WHERE id = ?').bind(code).run();
      return;
    }

    let retraceData = null;
    try { retraceData = JSON.parse(room.retrace_questionnaire); } catch (e) { /* 解析失败 */ }
    if (!retraceData) {
      console.error('generateRetraceReport: invalid retrace data');
      await env.DB.prepare('UPDATE rooms SET retrace_status = "error" WHERE id = ?').bind(code).run();
      return;
    }

    const retraceRole = retraceData.role || room.retrace_role || 'b';
    const originalRole = retraceRole === 'a' ? 'b' : 'a';

    // 获取原始角色的问卷数据
    const originalQ = await env.DB.prepare(
      'SELECT dimensions_json, individual_report_json, mira_type FROM couple_questionnaires WHERE room_code = ? AND role = ?'
    ).bind(code, originalRole).first();

    if (!originalQ) {
      console.error('generateRetraceReport: original questionnaire not found');
      await env.DB.prepare('UPDATE rooms SET retrace_status = "error" WHERE id = ?').bind(code).run();
      return;
    }

    const originalDims = JSON.parse(originalQ.dimensions_json || '{}');
    const retraceDims = retraceData.dimensions || {};
    const originalReport = JSON.parse(originalQ.individual_report_json || '{}');

    // 构建维度文本
    const originalDimText = COUPLE_DIMENSIONS.map(d => {
      return `${d.id}. ${d.label}: ${originalDims[d.id] || '无'}`;
    }).join('\n');

    const retraceDimText = COUPLE_DIMENSIONS.map(d => {
      return `${d.id}. ${d.label}: ${retraceDims[d.id] || '无'}`;
    }).join('\n');

    // 关系原型
    const archetype = getRelationshipArchetype(
      originalRole === 'a' ? (originalQ.mira_type || 'ST') : (retraceData.miraType || 'ST'),
      originalRole === 'a' ? (retraceData.miraType || 'ST') : (originalQ.mira_type || 'ST')
    );

    const prompt = `你是Mirror的双人关系分析模块。现在进行回溯分析：双方最初描述了不同的事件，现在${retraceRole === 'a' ? 'A' : 'B'}围绕${originalRole === 'a' ? 'A' : 'B'}的事件重新填写了18维度问卷。

【回溯背景】
- 原始报告事件对齐：${sharedReport.eventAlignment || 'different'}
- 原始报告事件分析：${sharedReport.eventAnalysis || '双方描述了不同的事件'}
- 原始报告建议：${sharedReport.retraceSuggestion || '建议回溯'}

【${originalRole === 'a' ? 'A' : 'B'}的原始问卷（事件提供方）】
${originalDimText}

【${originalRole === 'a' ? 'A' : 'B'}的MIRA类型】${originalQ.mira_type || '未知'}

【${retraceRole === 'a' ? 'A' : 'B'}的回溯问卷（围绕对方事件重新填写）】
${retraceDimText}

【${retraceRole === 'a' ? 'A' : 'B'}的MIRA类型】${retraceData.miraType || '未知'}

【原始共同报告的关键信息】
- 共同需求：${sharedReport.commonNeed || '无'}
- 共同误读：${sharedReport.commonMisread || '无'}
- 互动模式：${sharedReport.interactionPattern || '无'}
- 成长方向：${sharedReport.growthDirection || '无'}

请生成回溯分析报告，严格以JSON格式回复（不要包含任何其他文字），包含以下字段：
- retraceSummary: 回溯分析总结（3-4句话），说明围绕同一事件后双方视角的变化
- newCommonalities: 对象，包含五个维度的共同点（回溯后的新发现）：
  - fact: 事实层面新的共同点（1句话）
  - emotion: 情绪模式新的共通点（1句话）
  - need: 需求层面新的共通点（1句话）
  - misread: 误读模式新的共通点（1句话）
  - suggest: 行动意愿新的共通点（1句话）
- newCrossValidation: 对象，包含 aMisread（A对B的误读，1句话）和 bMisread（B对A的误读，1句话）和 aActualIntent（A的真实意图，1句话）和 bActualIntent（B的真实意图，1句话）
- improvement: 相比原始报告，回溯后的改善点（2-3句话）
- remainingIssue: 回溯后仍然存在的问题或需要继续关注的点（2-3句话）
- updatedActionableSteps: 数组，2-3条基于回溯结果的具体建议
- eventResolution: 事件解决程度评估（"已理解"或"部分理解"或"仍需沟通"），附1句话说明
- archetypeName: "${archetype.name}"
- archetypeDesc: "${archetype.desc}"`;

    const result = await callAI(env, prompt, 'couple', []);

    if (result.error) {
      console.error('generateRetraceReport AI error:', result.error);
      await env.DB.prepare('UPDATE rooms SET retrace_status = "error" WHERE id = ?').bind(code).run();
      return;
    }

    // 补充数据
    result.retraceRole = retraceRole;
    result.originalRole = originalRole;
    result.archetype = archetype;

    const retraceJson = JSON.stringify(result);
    await env.DB.prepare(
      'UPDATE rooms SET retrace_report = ?, retrace_status = "completed" WHERE id = ?'
    ).bind(retraceJson, code).run();

    console.log('generateRetraceReport completed for room:', code);
  } catch (err) {
    console.error('generateRetraceReport error:', err.message);
    await env.DB.prepare('UPDATE rooms SET retrace_status = "error" WHERE id = ?').bind(code).run();
  }
}

// ═══ 最终总结报告生成 ═══
async function generateFinalSummaryReport(env, code) {
  try {
    const room = await env.DB.prepare(
      'SELECT id, shared_report, retrace_report, retrace_status FROM rooms WHERE id = ?'
    ).bind(code).first();
    if (!room || !room.shared_report) {
      console.error('generateFinalSummaryReport: no shared report');
      return;
    }

    let sharedReport = null;
    try { sharedReport = JSON.parse(room.shared_report); } catch (e) { /* 解析失败 */ }

    let retraceReport = null;
    if (room.retrace_report) {
      try { retraceReport = JSON.parse(room.retrace_report); } catch (e) { /* 解析失败 */ }
    }

    // 获取双方问卷数据
    const qA = await env.DB.prepare(
      'SELECT dimensions_json, mira_type FROM couple_questionnaires WHERE room_code = ? AND role = "a"'
    ).bind(code).first();
    const qB = await env.DB.prepare(
      'SELECT dimensions_json, mira_type FROM couple_questionnaires WHERE room_code = ? AND role = "b"'
    ).bind(code).first();

    const archetype = getRelationshipArchetype(qA?.mira_type || 'ST', qB?.mira_type || 'ST');

    const prompt = `你是Mirror的双人关系分析模块，现在需要生成最终总结报告。这份报告汇总了整个分析过程中两个事件的解决情况。

【关系原型】${archetype.name}（${archetype.pattern}）

【A的MIRA类型】${qA?.mira_type || '未知'}
【B的MIRA类型】${qB?.mira_type || '未知'}

【第一份报告（原始共同报告）关键信息】
- 事件对齐：${sharedReport?.eventAlignment || '未知'}
- 事件分析：${sharedReport?.eventAnalysis || '未知'}
- 共同需求：${sharedReport?.commonNeed || '无'}
- 共同误读：${sharedReport?.commonMisread || '无'}
- 互动模式：${sharedReport?.interactionPattern || '无'}
- 成长方向：${sharedReport?.growthDirection || '无'}
- 可执行建议：${JSON.stringify(sharedReport?.actionableSteps || [])}

${retraceReport ? `【第二份报告（回溯报告）关键信息】
- 回溯总结：${retraceReport.retraceSummary || '无'}
- 改善点：${retraceReport.improvement || '无'}
- 仍存在的问题：${retraceReport.remainingIssue || '无'}
- 事件解决程度：${retraceReport.eventResolution || '未知'}
- 更新后的建议：${JSON.stringify(retraceReport.updatedActionableSteps || [])}` : '【无回溯报告，事件一致无需回溯】'}

请生成最终总结报告，严格以JSON格式回复（不要包含任何其他文字），包含以下字段：
- overallSummary: 整体关系总结（3-4句话），涵盖整个分析过程的核心发现
- eventResolutionStatus: 对象，包含两个事件的解决情况：
  - event1: ${sharedReport?.eventAlignment === 'same' ? '同一事件的解决情况' : '第一个事件（双方原始描述）的解决情况'}（2-3句话）
  - event2: ${retraceReport ? '回溯事件的解决情况（2-3句话）' : '无需回溯，事件一致'}
- keyInsights: 数组，3-4条整个过程中最重要的关系洞察
- relationshipProgress: 关系进展评估（2-3句话），说明通过这次分析双方可以期待的变化
- finalRecommendations: 数组，3-4条最终的长期关系建议
- growthMilestone: 成长里程碑（1-2句话），标注这次分析在关系成长中的意义
- archetypeName: "${archetype.name}"
- archetypeDesc: "${archetype.desc}"
- aMiraType: "${qA?.mira_type || ''}"
- bMiraType: "${qB?.mira_type || ''}"`;

    const result = await callAI(env, prompt, 'couple', []);

    if (result.error) {
      console.error('generateFinalSummaryReport AI error:', result.error);
      await env.DB.prepare('UPDATE rooms SET final_status = "error" WHERE id = ?').bind(code).run();
      return;
    }

    result.archetype = archetype;

    const finalJson = JSON.stringify(result);
    await env.DB.prepare(
      'UPDATE rooms SET final_report = ?, final_status = "completed" WHERE id = ?'
    ).bind(finalJson, code).run();

    console.log('generateFinalSummaryReport completed for room:', code);
  } catch (err) {
    console.error('generateFinalSummaryReport error:', err.message);
    await env.DB.prepare('UPDATE rooms SET final_status = "error" WHERE id = ?').bind(code).run();
  }
}

// 复制双人模式重构后的房间记录到双方 user_room_records
async function copyCoupleRoomToUserRecords(env, code, qA, qB, sharedReport) {
  const room = await env.DB.prepare('SELECT a_uid, b_uid, expires_at FROM rooms WHERE id = ?').bind(code).first();
  if (!room) return;

  const sharedJson = JSON.stringify(sharedReport);
  const aReport = qA.individual_report_json || '{}';
  const bReport = qB.individual_report_json || '{}';

  // A的记录
  if (room.a_uid) {
    const existA = await env.DB.prepare('SELECT id FROM user_room_records WHERE room_code = ? AND user_id = ?').bind(code, room.a_uid).first();
    if (!existA) {
      await env.DB.prepare(
        'INSERT INTO user_room_records (user_id, room_code, role, my_mira_type, partner_mira_type, shared_report_json, my_insight_json, partner_insight_json, created_at, source_room_expires_at) VALUES (?, ?, "a", ?, ?, ?, ?, ?, datetime("now"), ?)'
      ).bind(room.a_uid, code, qA.mira_type || '', qB.mira_type || '', sharedJson, aReport, bReport, room.expires_at).run();
    }
  }

  // B的记录
  if (room.b_uid) {
    const existB = await env.DB.prepare('SELECT id FROM user_room_records WHERE room_code = ? AND user_id = ?').bind(code, room.b_uid).first();
    if (!existB) {
      await env.DB.prepare(
        'INSERT INTO user_room_records (user_id, room_code, role, my_mira_type, partner_mira_type, shared_report_json, my_insight_json, partner_insight_json, created_at, source_room_expires_at) VALUES (?, ?, "b", ?, ?, ?, ?, ?, datetime("now"), ?)'
      ).bind(room.b_uid, code, qB.mira_type || '', qA.mira_type || '', sharedJson, bReport, aReport, room.expires_at).run();
    }
  }
}

// 异步保存单人分析结果到 single_analyses 表（同时写入 analysis_history 和 insight_diaries）
async function saveSingleAnalysis(env, prompt, result, uid = null) {
  try {
    const userInput = base64Encode((prompt || '').substring(0, 500));
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
