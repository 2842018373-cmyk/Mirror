-- ══════════════════════════════════════════ Mirror D1 数据库表结构 ══════════════════════════════════════════

CREATE TABLE IF NOT EXISTS rooms (
  id TEXT PRIMARY KEY,           -- 4位房间码
  status TEXT DEFAULT 'waiting', -- waiting/ready/a_input/b_input/analyzing/analyzed/completed
  a_input TEXT,                  -- A的原文（base64加密）
  b_input TEXT,                  -- B的原文（base64加密）
  a_insight TEXT,                -- A的洞察摘要（JSON）
  b_insight TEXT,                -- B的洞察摘要（JSON）
  a_consent INTEGER DEFAULT 0,   -- A是否同意生成共同报告
  b_consent INTEGER DEFAULT 0,   -- B是否同意生成共同报告
  shared_report TEXT,            -- 共同报告（JSON）
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME            -- 24小时后过期
);

-- 创建索引
CREATE INDEX IF NOT EXISTS idx_rooms_status ON rooms(status);
CREATE INDEX IF NOT EXISTS idx_rooms_expires ON rooms(expires_at);

-- ══════════════════════════════════════════ 用户系统 ══════════════════════════════════════════

-- 用户表（支持游客和手机号两种身份）
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guest_id TEXT UNIQUE,           -- 游客UUID（游客模式时生成）
  phone TEXT UNIQUE,              -- 手机号（手机号登录时填入，游客为NULL）
  nickname TEXT,                  -- 昵称（可选）
  mira_type TEXT,                 -- 用户最新的MIRA人格类型
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_users_guest ON users(guest_id);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);

-- 验证码表（替代FC内存存储）
CREATE TABLE IF NOT EXISTS verify_codes (
  phone TEXT PRIMARY KEY,
  code TEXT NOT NULL,             -- 6位数字验证码
  expire_at INTEGER NOT NULL,     -- 过期时间戳（毫秒，5分钟有效期）
  attempts INTEGER DEFAULT 0,      -- 已尝试错误次数
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
