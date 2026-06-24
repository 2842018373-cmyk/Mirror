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
