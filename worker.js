// ══════════════════════════════════════════ Mirror API Worker ══════════════════════════════════════════
// Cloudflare Workers + D1 后端
// 功能：房间管理 + AI 代理 + 数据隔离

// CORS 配置
const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
};

// 生成 4 位房间码
function generateRoomCode() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 4; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

// 统一响应
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

// 主处理函数
export default {
  async fetch(request, env, ctx) {
    // 处理 CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      // ══════════════════════════════════════════ 房间管理 API ══════════════════════════════════════════

      // 创建房间
      if (path === '/api/room' && request.method === 'POST') {
        const code = generateRoomCode();
        await env.DB.prepare(
          'INSERT INTO rooms (id, status, created_at, expires_at) VALUES (?, ?, datetime("now"), datetime("now", "+24 hours"))'
        ).bind(code, 'waiting').run();
        return jsonResponse({ code, status: 'waiting' });
      }

      // 加入房间
      if (path.match(/^\/api\/room\/[A-Z0-9]{4}\/join$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404);
        if (room.status !== 'waiting') return jsonResponse({ error: '房间已满' }, 400);

        await env.DB.prepare('UPDATE rooms SET status = ? WHERE id = ?').bind('ready', code).run();
        return jsonResponse({ code, status: 'ready' });
      }

      // 获取房间状态
      if (path.match(/^\/api\/room\/[A-Z0-9]{4}$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT id, status, a_consent, b_consent, created_at FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404);
        return jsonResponse(room);
      }

      // 提交输入（A 或 B）
      if (path.match(/^\/api\/room\/[A-Z0-9]{4}\/input$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        const { role, text } = await request.json();
        if (!['a', 'b'].includes(role)) return jsonResponse({ error: '角色错误' }, 400);

        const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404);

        // 加密存储原文（简单 base64，生产环境应使用更安全的加密）
        const encrypted = btoa(unescape(encodeURIComponent(text)));
        const field = role === 'a' ? 'a_input' : 'b_input';
        const statusField = role === 'a' ? 'a_inputted' : 'b_inputted';

        await env.DB.prepare(`UPDATE rooms SET ${field} = ?, status = CASE WHEN status = 'ready' THEN '${role}_input' WHEN status = '${role === 'a' ? 'b' : 'a'}_input' THEN 'analyzing' ELSE status END WHERE id = ?`).bind(encrypted, code).run();

        // 如果双方都输入了，触发 AI 分析
        if (room.status === 'analyzing' || (room.a_input && role === 'b') || (room.b_input && role === 'a')) {
          // 异步触发 AI 分析
          ctx.waitUntil(analyzeCouple(env, code));
        }

        return jsonResponse({ success: true, status: 'input_received' });
      }

      // 获取洞察摘要（非原文）
      if (path.match(/^\/api\/room\/[A-Z0-9]{4}\/insight$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const { role } = url.searchParams;
        const room = await env.DB.prepare('SELECT a_insight, b_insight, status FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404);

        // 只能看到对方的洞察，不能看到自己的
        const insight = role === 'a' ? room.b_insight : room.a_insight;
        return jsonResponse({ insight: insight || null, status: room.status });
      }

      // 同意生成共同报告
      if (path.match(/^\/api\/room\/[A-Z0-9]{4}\/consent$/) && request.method === 'POST') {
        const code = path.split('/')[3];
        const { role } = await request.json();
        const field = role === 'a' ? 'a_consent' : 'b_consent';

        await env.DB.prepare(`UPDATE rooms SET ${field} = 1 WHERE id = ?`).bind(code).run();

        const room = await env.DB.prepare('SELECT a_consent, b_consent, status FROM rooms WHERE id = ?').bind(code).first();

        // 双方都同意，生成共同报告
        if (room.a_consent && room.b_consent && room.status === 'analyzed') {
          ctx.waitUntil(generateSharedReport(env, code));
        }

        return jsonResponse({ success: true, bothConsented: room.a_consent && room.b_consent });
      }

      // 获取共同报告
      if (path.match(/^\/api\/room\/[A-Z0-9]{4}\/report$/) && request.method === 'GET') {
        const code = path.split('/')[3];
        const room = await env.DB.prepare('SELECT shared_report, status, a_consent, b_consent FROM rooms WHERE id = ?').bind(code).first();
        if (!room) return jsonResponse({ error: '房间不存在' }, 404);
        if (!room.a_consent || !room.b_consent) return jsonResponse({ error: '双方未同意' }, 403);

        return jsonResponse({ report: room.shared_report, status: room.status });
      }

      // ══════════════════════════════════════════ AI 代理 API ══════════════════════════════════════════

      // 单人模式 AI 分析
      if (path === '/api/analyze' && request.method === 'POST') {
        const { prompt, mode, history } = await request.json();
        const result = await callAI(env, prompt, mode, history);
        return jsonResponse(result);
      }

      // 写信模式
      if (path === '/api/letter' && request.method === 'POST') {
        const { prompt, history } = await request.json();
        const result = await callAI(env, prompt, 'letter', history);
        return jsonResponse(result);
      }

      // 404
      return jsonResponse({ error: 'Not Found' }, 404);

    } catch (err) {
      return jsonResponse({ error: err.message }, 500);
    }
  },
};

// 调用 Agnes AI
async function callAI(env, prompt, mode, history) {
  const systemPrompt = mode === 'letter'
    ? '你是 Mirror，一个关系理解与表达操作系统...写信模式...'
    : '你是 Mirror，一个关系理解与表达操作系统...单人模式...';

  const messages = [
    { role: 'system', content: systemPrompt },
    ...(history || []),
    { role: 'user', content: prompt },
  ];

  const response = await fetch('https://apihub.agnes-ai.com/v1/chat/completions', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${env.AI_API_KEY}`,
    },
    body: JSON.stringify({
      model: 'agnes-1.5-flash',
      messages,
      temperature: 0.7,
      max_tokens: 2000,
    }),
  });

  const data = await response.json();
  const content = data.choices?.[0]?.message?.content || '';

  // 解析 JSON
  try {
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
  } catch (e) {
    // 解析失败返回原始内容
  }

  return { raw: content, error: 'JSON解析失败' };
}

// 双人分析：分别分析 A 和 B
async function analyzeCouple(env, code) {
  const room = await env.DB.prepare('SELECT * FROM rooms WHERE id = ?').bind(code).first();
  if (!room || !room.a_input || !room.b_input) return;

  // 解密原文
  const aText = decodeURIComponent(escape(atob(room.a_input)));
  const bText = decodeURIComponent(escape(atob(room.b_input)));

  // 分别分析 A 和 B
  const [aResult, bResult] = await Promise.all([
    callAI(env, `分析以下用户的描述：${aText}`, 'single', []),
    callAI(env, `分析以下用户的描述：${bText}`, 'single', []),
  ]);

  // 提取洞察摘要（不含原文）
  const aInsight = JSON.stringify({
    fact: aResult.fact,
    emotion: aResult.emotion,
    need: aResult.need,
    misread: aResult.misread,
    status: aResult.status,
  });

  const bInsight = JSON.stringify({
    fact: bResult.fact,
    emotion: bResult.emotion,
    need: bResult.need,
    misread: bResult.misread,
    status: bResult.status,
  });

  await env.DB.prepare(
    'UPDATE rooms SET a_insight = ?, b_insight = ?, status = ? WHERE id = ?'
  ).bind(aInsight, bInsight, 'analyzed', code).run();
}

// 生成共同报告
async function generateSharedReport(env, code) {
  const room = await env.DB.prepare('SELECT a_insight, b_insight FROM rooms WHERE id = ?').bind(code).first();
  if (!room) return;

  const aInsight = JSON.parse(room.a_insight || '{}');
  const bInsight = JSON.parse(room.b_insight || '{}');

  const prompt = `基于以下两个人的洞察摘要，生成共同建议：

A的核心需求：${aInsight.need}
A的误读：${aInsight.misread}

B的核心需求：${bInsight.need}
B的误读：${bInsight.misread}

请生成共同报告，包含：
1. 共同需求
2. 共同误读点
3. 互动模式
4. 可执行的改善方向

输出 JSON：{"commonNeed":"","commonMisread":"","interactionPattern":"","suggest":""}`;

  const result = await callAI(env, prompt, 'couple', []);

  await env.DB.prepare(
    'UPDATE rooms SET shared_report = ?, status = ? WHERE id = ?'
  ).bind(JSON.stringify(result), 'completed', code).run();
}
