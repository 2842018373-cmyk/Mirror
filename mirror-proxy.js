/**
 * Mirror Proxy - Cloudflare Worker
 * 
 * 部署步骤：
 * 1. 注册 Cloudflare 账号 (cloudflare.com) - 免费
 * 2. 进入 Workers & Pages → 创建 Worker
 * 3. 把下面代码粘贴进去，保存
 * 4. 设置环境变量：AGENS_API_KEY = 你的真实 API Key
 * 5. 复制 Worker 的 URL，替换到 mirror-cover.html 的 MIRROR_API_URL
 */

export default {
  async fetch(request, env, ctx) {
    // 只允许特定域名访问（防止别人盗用你的代理）
    const allowedOrigins = [
      'http://localhost',           // 本地开发
      'http://localhost:3000',
      'http://127.0.0.1',
      // 'https://你的域名.com',    // 部署后加上你的真实域名
    ];
    
    const origin = request.headers.get('Origin') || '';
    const isAllowed = allowedOrigins.some(o => origin.startsWith(o)) || origin === '';
    
    // 处理 CORS 预检请求
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
          'Access-Control-Allow-Methods': 'POST, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type',
          'Access-Control-Max-Age': '86400',
        }
      });
    }

    // 只接受 POST 请求
    if (request.method !== 'POST') {
      return new Response(JSON.stringify({ error: 'Method not allowed' }), {
        status: 405,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
        }
      });
    }

    try {
      // 读取用户传来的请求体
      const body = await request.json();
      
      // 从环境变量读取 API Key（永远不会暴露给前端）
      const apiKey = env.AGENS_API_KEY;
      if (!apiKey) {
        return new Response(JSON.stringify({ error: 'Server configuration error' }), {
          status: 500,
          headers: {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
          }
        });
      }

      // 调用真实的 Agens AI API
      const response = await fetch('https://api.agens.ai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${apiKey}`
        },
        body: JSON.stringify(body)
      });

      // 读取响应
      const responseData = await response.text();

      // 返回给前端（不带任何 Key）
      return new Response(responseData, {
        status: response.status,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
        }
      });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 500,
        headers: {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': isAllowed ? origin : allowedOrigins[0],
        }
      });
    }
  }
};
