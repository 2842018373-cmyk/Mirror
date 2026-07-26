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

-- 用户表（支持游客、手机号、密码三种登录方式）
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  guest_id TEXT UNIQUE,           -- 游客UUID（游客模式时生成）
  phone TEXT UNIQUE,              -- 手机号（手机号登录时填入，游客为NULL）
  password_hash TEXT,             -- 密码哈希（SHA-256(salt+password)，密码登录时使用）
  password_salt TEXT,              -- 密码盐值（随机生成）
  nickname TEXT,                  -- 昵称（可选）
  mira_type TEXT,                 -- 用户最新的MIRA人格类型
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_users_guest ON users(guest_id);
CREATE INDEX IF NOT EXISTS idx_users_phone ON users(phone);

-- 密码登录初始化：为已有手机号用户设置默认密码 1234
-- ALTER TABLE users ADD COLUMN password_hash TEXT;
-- ALTER TABLE users ADD COLUMN password_salt TEXT;

-- 验证码表（替代FC内存存储）
CREATE TABLE IF NOT EXISTS verify_codes (
  phone TEXT PRIMARY KEY,
  code TEXT NOT NULL,             -- 6位数字验证码
  expire_at INTEGER NOT NULL,     -- 过期时间戳（毫秒，5分钟有效期）
  attempts INTEGER DEFAULT 0,      -- 已尝试错误次数
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- 短信发送日志表（D1持久化限流，防多实例绕过）
-- 限制：同一手机号每天最多10次；同一IP每分钟最多3次、每天最多20次
CREATE TABLE IF NOT EXISTS sms_send_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  phone TEXT NOT NULL,             -- 发送目标手机号
  ip TEXT NOT NULL,                -- 请求来源IP
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,  -- 发送时间（datetime字符串，用于日限额查询）
  created_at_ms INTEGER NOT NULL   -- 发送时间戳（毫秒，用于分钟级限额查询）
);

CREATE INDEX IF NOT EXISTS idx_sms_log_phone_time ON sms_send_log(phone, created_at);
CREATE INDEX IF NOT EXISTS idx_sms_log_ip_time ON sms_send_log(ip, created_at_ms);
CREATE INDEX IF NOT EXISTS idx_sms_log_ip_date ON sms_send_log(ip, created_at);

-- ══════════════════════════════════════════ 个人中心相关表 ══════════════════════════════════════════

-- 镜像对话分析记录表（新增 user_id + report_json 字段，通过 ALTER 增量添加）
-- ALTER TABLE single_analyses ADD COLUMN user_id INTEGER;
-- ALTER TABLE single_analyses ADD COLUMN report_json TEXT DEFAULT '{}';
CREATE INDEX IF NOT EXISTS idx_single_analyses_user ON single_analyses(user_id, created_at);

-- MIRA 测试记录表（新增 user_id + deep_text 字段，通过 ALTER 增量添加）
-- ALTER TABLE mira_tests ADD COLUMN user_id INTEGER;
-- ALTER TABLE mira_tests ADD COLUMN deep_text TEXT DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_mira_tests_user ON mira_tests(user_id, created_at);

-- 房间表新增用户关联字段（通过 ALTER 增量添加）
-- ALTER TABLE rooms ADD COLUMN a_uid INTEGER;
-- ALTER TABLE rooms ADD COLUMN b_uid INTEGER;

-- 双人房间记录副本表（永久保存，房间24h过期后仍可回看）
CREATE TABLE IF NOT EXISTS user_room_records (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,              -- 归属用户
  room_code TEXT NOT NULL,               -- 原房间码（快照）
  role TEXT NOT NULL,                    -- 该用户在房间中的角色 'a'/'b'
  partner_mira_type TEXT,                -- 对方的 MIRA 类型
  my_mira_type TEXT,                     -- 自己的 MIRA 类型
  shared_report_json TEXT,               -- 共同报告完整 JSON
  my_insight_json TEXT,                  -- 自己的洞察 JSON
  partner_insight_json TEXT,             -- 对方的洞察 JSON（已授权可见）
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  source_room_expires_at DATETIME        -- 原房间过期时间（仅记录用）
);

CREATE INDEX IF NOT EXISTS idx_user_room_records_user ON user_room_records(user_id, created_at);
