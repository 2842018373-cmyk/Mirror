/**
 * Mirror 认证服务 - 阿里云函数计算 (FC) 代码
 * 
 * 部署方式：阿里云函数计算 (Node.js 18+)
 * 触发器：HTTP 触发器 (API网关)
 * 
 * 环境变量配置：
 * - ALIYUN_ACCESS_KEY: 阿里云 AccessKey
 * - ALIYUN_SECRET_KEY: 阿里云 SecretKey
 * - SMS_SIGN_NAME: 短信签名（需在阿里云短信服务中审核通过）
 * - SMS_TEMPLATE_CODE: 短信模板 CODE
 * - SMS_CODE_EXPIRE: 验证码有效期（秒，默认300）
 */

const SMSClient = require('@alicloud/sms-sdk');

// 验证码存储（内存，生产环境建议用 Redis 或 OSS）
const codeStore = {};

// 定时清理过期验证码
setInterval(() => {
  const now = Date.now();
  for (const key in codeStore) {
    if (codeStore[key].expireAt < now) {
      delete codeStore[key];
    }
  }
}, 60000);

/**
 * 生成6位随机验证码
 */
function generateCode() {
  return String(Math.floor(100000 + Math.random() * 900000));
}

/**
 * 发送验证码
 */
async function sendSms(phone, code) {
  const accessKeyId = process.env.ALIYUN_ACCESS_KEY;
  const accessKeySecret = process.env.ALIYUN_SECRET_KEY;
  const signName = process.env.SMS_SIGN_NAME;
  const templateCode = process.env.SMS_TEMPLATE_CODE;

  if (!accessKeyId || !accessKeySecret) {
    throw new Error('未配置阿里云 AccessKey');
  }

  const smsClient = new SMSClient({
    accessKeyId,
    secretAccessKey: accessKeySecret
  });

  const result = await smsClient.sendSMS({
    PhoneNumbers: phone,
    SignName: signName || 'Mirror',
    TemplateCode: templateCode || 'SMS_123456789',
    TemplateParam: JSON.stringify({ code })
  });

  if (result.Code === 'OK') {
    return { success: true, bizId: result.BizId };
  }
  throw new Error(`短信发送失败: ${result.Code}`);
}

/**
 * 校验手机号格式（中国大陆）
 */
function isValidChinesePhone(phone) {
  return /^1[3-9]\d{9}$/.test(phone);
}

/**
 * 主入口
 */
exports.handler = async (event, context) => {
  try {
    const body = JSON.parse(event.toString());
    const { action, phone, code, captcha } = body;

    // ============ 机器人检测 ============
    if (captcha !== undefined) {
      // 前端生成简单的数学题，如 { question: '7+8', answer: 15 }
      // 这里由前端验证，服务端也可以加一道题
      if (typeof captcha.answer !== 'number' || captcha.answer !== captcha.expected) {
        return {
          statusCode: 400,
          body: JSON.stringify({ success: false, message: '验证失败，请重试' })
        };
      }
    }

    switch (action) {

      // ============ 发送验证码 ============
      case 'sendCode': {
        if (!isValidChinesePhone(phone)) {
          return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: '手机号格式不正确' })
          };
        }

        const code = generateCode();
        const expireIn = parseInt(process.env.SMS_CODE_EXPIRE) || 300;

        codeStore[phone] = {
          code: code,
          expireAt: Date.now() + expireIn * 1000,
          attempts: 0
        };

        await sendSms(phone, code);

        // 记录日志但不返回验证码本身
        console.log(`[SMS] 验证码已发送至 ${phone}，有效期 ${expireIn}秒`);

        return {
          statusCode: 200,
          body: JSON.stringify({
            success: true,
            message: '验证码已发送',
            expireIn: expireIn
          })
        };
      }

      // ============ 验证验证码并登录 ============
      case 'verifyCode': {
        if (!phone || !code) {
          return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: '参数不完整' })
          };
        }

        const record = codeStore[phone];

        if (!record) {
          return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: '请先获取验证码' })
          };
        }

        if (Date.now() > record.expireAt) {
          delete codeStore[phone];
          return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: '验证码已过期，请重新获取' })
          };
        }

        record.attempts++;

        if (record.attempts > 5) {
          delete codeStore[phone];
          return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: '尝试次数过多，请重新获取验证码' })
          };
        }

        if (record.code !== code) {
          return {
            statusCode: 400,
            body: JSON.stringify({ success: false, message: '验证码错误' })
          };
        }

        // 验证成功，清除验证码
        delete codeStore[phone];

        // 生成用户 token（生产环境用 JWT）
        const token = generateToken(phone);

        return {
          statusCode: 200,
          body: JSON.stringify({
            success: true,
            message: '登录成功',
            token: token,
            user: {
              phone: phone,
              createdAt: Date.now()
            }
          })
        };
      }

      default:
        return {
          statusCode: 400,
          body: JSON.stringify({ success: false, message: '未知操作' })
        };
    }
  } catch (err) {
    console.error('[Error]', err);
    return {
      statusCode: 500,
      body: JSON.stringify({ success: false, message: '服务异常，请稍后重试' })
    };
  }
};

/**
 * 生成简单 Token（生产环境请用 JWT）
 */
function generateToken(phone) {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64');
  const payload = Buffer.from(JSON.stringify({
    sub: phone,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + 86400 * 7 // 7天
  })).toString('base64');
  return `${header}.${payload}.mirror_demo_signature`;
}