// ══════════════════════════════════════════ Mirror API Worker v2 ══════════════════════════════════════════
// Cloudflare Workers + D1 后端
// v2: 安全加固 + 数据隔离修复 + 错误处理 + 速率限制

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
  if (ALLOWED_ORIGINS.includes(origin)) {
    return {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };
  }
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGINS[0],
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
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

// 生成 6 位房间码（从 4 位升级，组合数从 81 万提升到 10 亿+）
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

// 主处理函数
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

    try {
      // ══════════════════════════════════════════ 房间管理 API ══════════════════════════════════════════

      // 创建房间（速率限制：每 IP 每分钟 5 次）
      if (path === '/api/room' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'create_room', 5, 60000)) {
          return jsonResponse({ error: '创建房间过于频繁，请稍后再试' }, 429, origin);
        }

        const code = generateRoomCode();
        // 检查房间码是否已存在（极小概率碰撞）
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

      // 提交输入（A 或 B）
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

        // 状态校验：只允许在 ready 或对方已输入时提交
        const expectedStatus = validatedRole === 'a' ? 'ready' : 'ready';
        const otherInputField = validatedRole === 'a' ? 'b_input' : 'a_input';
        const otherRole = validatedRole === 'a' ? 'b' : 'a';

        if (room.status !== 'ready' && room.status !== `${otherRole}_input`) {
          return jsonResponse({ error: '当前状态不允许提交输入' }, 400, origin);
        }

        // 检查是否已提交过
        const myInputField = validatedRole === 'a' ? 'a_input' : 'b_input';
        if (room[myInputField]) {
          return jsonResponse({ error: '你已经提交过输入了' }, 400, origin);
        }

        // 编码存储
        const encoded = btoa(unescape(encodeURIComponent(text)));

        // 安全的参数化更新（避免 SQL 拼接）
        const newStatus = room[otherInputField] ? 'analyzing' : `${validatedRole}_input`;
        await env.DB.prepare(
          `UPDATE rooms SET ${myInputField} = ?, status = ? WHERE id = ?`
        ).bind(encoded, newStatus, code).run();

        // 如果双方都输入了，触发 AI 分析
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

        // 检查是否已同意
        const consentField = validatedRole === 'a' ? 'a_consent' : 'b_consent';
        if (room[consentField]) {
          return jsonResponse({ success: true, bothConsented: !!room.a_consent && !!room.b_consent, message: '你已经同意过了' }, 200, origin);
        }

        // 安全更新
        await env.DB.prepare(`UPDATE rooms SET ${consentField} = 1 WHERE id = ?`).bind(code).run();

        const updated = await env.DB.prepare('SELECT a_consent, b_consent FROM rooms WHERE id = ?').bind(code).first();
        const bothConsented = !!updated.a_consent && !!updated.b_consent;

        // 双方都同意，生成共同报告
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

      // 全局请求体大小限制（100KB）
      const contentLength = request.headers.get('Content-Length') || 0;
      if (parseInt(contentLength) > 102400) {
        return jsonResponse({ error: '请求体过大' }, 413, origin);
      }

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

        const result = await callAI(env, prompt, mode || 'single', history || []);

        // 分析成功后，异步存入 single_analyses 表
        if (!result.error && (mode || 'single') === 'single') {
          ctx.waitUntil(saveSingleAnalysis(env, prompt, result));
        }

        return jsonResponse(result, 200, origin);
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
        return jsonResponse(result, 200, origin);
      }

      // MIRA 人格测试判题
      if (path === '/api/mira-quiz' && request.method === 'POST') {
        if (!checkRateLimit(clientIP, 'mira_quiz', 5, 60000)) {
          return jsonResponse({ error: '请求过于频繁，请稍后再试' }, 429, origin);
        }

        let body;
        try { body = await request.json(); } catch (e) { return jsonResponse({ error: '请求格式错误' }, 400, origin); }

        const { prompt } = body;
        if (!prompt || typeof prompt !== 'string') return jsonResponse({ error: 'prompt 不能为空' }, 400, origin);
        if (prompt.length > 15000) return jsonResponse({ error: 'prompt 过长' }, 400, origin);

        const result = await callAI(env, prompt, 'quiz', []);
        return jsonResponse(result, 200, origin);
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
        return jsonResponse(result, 200, origin);
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

          return jsonResponse({ success: true, message: '数据库表创建/验证完成' }, 200, origin);
        } catch (err) {
          console.error('init-db error:', err.message);
          return jsonResponse({ error: '数据库初始化失败' }, 500, origin);
        }
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
      // 不泄露内部错误细节
      console.error('Worker error:', err.message, err.stack);
      return jsonResponse({ error: '服务器内部错误' }, 500, origin);
    }
  },
};

// 调用 Agnes AI（带超时和错误处理）
async function callAI(env, prompt, mode, history) {
  const systemPrompts = {
    single: '你是 Mirror，一个关系理解与表达操作系统。你擅长通过5层深度提问（事实→情绪→需求→意义→行动）来理解用户的情感关系状态。请严格以JSON格式回复（不要包含任何其他文字），包含以下字段：fact(事实摘要)、emotion(情绪识别)、need(核心需求)、misread(可能误读)、misreadType(误读类型：状态误读/行为误读/表达误读/自我投射)、status(关系状态评估)、miraType(MIRA关系原型代码，如ST/BO/DI等，根据表达方式×关注方向判断，D=暗影内敛/S=柔光温和/B=明光积极/R=辉光强烈 × O=向外/T=朝向/I=倾向/N=向内)、before(用户原始的攻击性表达，一句典型的话)、innerThought(用户内心的真实想法)、after(Mirror翻译后的非暴力表达)、insight(深度洞察，2-3句话)、suggest(改善建议，具体可执行)、summary(一句话总结用户真正想表达的)。',
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

  let response;
  try {
    response = await fetch('https://apihub.agnes-ai.com/v1/chat/completions', {
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
    });
  } catch (e) {
    return { error: 'AI 服务连接失败', raw: null };
  }

  if (!response.ok) {
    return { error: `AI 服务返回错误 (${response.status})`, raw: null };
  }

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content || '';

  if (!content) {
    return { error: 'AI 返回内容为空', raw: null };
  }

  // 解析 JSON
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

// 双人分析：分别分析 A 和 B（带错误处理）
async function analyzeCouple(env, code) {
  try {
    const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
    if (!room || !room.a_input || !room.b_input) {
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'analyzing'").bind(code).run();
      return;
    }

    // 解码原文
    const aText = decodeURIComponent(escape(atob(room.a_input)));
    const bText = decodeURIComponent(escape(atob(room.b_input)));

    // 分别分析 A 和 B
    const [aResult, bResult] = await Promise.all([
      callAI(env, `分析以下用户的情感关系描述，提取核心信息：${aText}`, 'single', []),
      callAI(env, `分析以下用户的情感关系描述，提取核心信息：${bText}`, 'single', []),
    ]);

    // 检查 AI 调用是否成功
    if (aResult.error || bResult.error) {
      console.error('AI analysis failed:', { a: aResult.error, b: bResult.error });
      await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ?").bind(code).run();
      return;
    }

    // 提取洞察摘要（安全取值，避免 undefined）
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
  } catch (err) {
    console.error('generateSharedReport error:', err.message);
    await env.DB.prepare("UPDATE rooms SET status = 'error' WHERE id = ? AND status = 'analyzed'").bind(code).run();
  }
}

// 异步保存单人分析结果到 single_analyses 表
async function saveSingleAnalysis(env, prompt, result) {
  try {
    // 截取摘要，避免超长
    const userInput = (prompt || '').substring(0, 500);
    await env.DB.prepare(
      'INSERT INTO single_analyses (user_input, fact, emotion, need, misread, status, insight, suggest, mira_type, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime("now"))'
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
    ).run();
  } catch (err) {
    console.error('saveSingleAnalysis error:', err.message);
  }
}
