CREATE TABLE IF NOT EXISTS visits (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT NOT NULL,
  ip            TEXT,
  country       TEXT,
  city          TEXT,
  asn           INTEGER,
  colo          TEXT,
  method        TEXT,
  path          TEXT,
  http_ver      TEXT,
  user_agent    TEXT,
  referer       TEXT,
  accept_lang   TEXT,
  tls_version   TEXT,
  tls_cipher    TEXT,
  headers_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_visits_ts ON visits(ts);
CREATE INDEX IF NOT EXISTS idx_visits_ip ON visits(ip);
