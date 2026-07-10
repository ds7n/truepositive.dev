-- True Positive /ip visit log. Recreate (drop + apply) to migrate.
DROP TABLE IF EXISTS visits;

CREATE TABLE visits (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT NOT NULL,
  ip            TEXT,
  -- geo
  country       TEXT,
  region        TEXT,
  region_code   TEXT,
  city          TEXT,
  postal_code   TEXT,
  continent     TEXT,
  metro_code    TEXT,
  timezone      TEXT,
  latitude      TEXT,
  longitude     TEXT,
  is_eu         TEXT,
  -- network
  asn           INTEGER,
  as_org        TEXT,
  colo          TEXT,
  -- request
  method        TEXT,
  path          TEXT,
  http_ver      TEXT,
  user_agent    TEXT,
  ua_browser    TEXT,
  ua_browser_version TEXT,
  ua_os         TEXT,
  ua_os_version TEXT,
  ua_device     TEXT,
  ua_engine     TEXT,
  ua_bot        INTEGER,
  referer       TEXT,
  accept_lang   TEXT,
  -- tls
  tls_version   TEXT,
  tls_cipher    TEXT,
  -- catch-all (redacted headers only)
  headers_json  TEXT
);
CREATE INDEX idx_visits_ts ON visits(ts);
CREATE INDEX idx_visits_ip ON visits(ip);
CREATE INDEX idx_visits_country ON visits(country);
