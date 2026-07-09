# /ip Request-Echo + Logging Endpoint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a content-negotiated `GET /ip` Cloudflare Pages Function that echoes the visitor's request/source info (HTML for browsers, JSON for curl) and logs each visit to a Cloudflare D1 database.

**Architecture:** A single Pages Function (`functions/ip.js`) delegates all data-shaping to pure functions in a sibling module (`functions/_lib.js`) so the leak-prone logic (HTML escaping, header redaction, field extraction, rendering) is unit-testable without a live Worker. The handler is thin glue: extract fields → best-effort D1 insert (isolated) → content-negotiate → respond. D1 is bound as `env.DB` via `wrangler.toml`.

**Tech Stack:** Cloudflare Pages Functions (Workers runtime, ES modules), Cloudflare D1 (SQLite), Node's built-in `node:test` for unit tests (zero dependencies). Plain HTML/CSS, no build step.

## Global Constraints

- No build step, no runtime dependencies, no tracking scripts. (Repo convention.)
- Test runner is Node's built-in `node:test` — **no** third-party test deps.
- `functions/_lib.js` must be pure ES modules importable by `node:test` directly (no Workers-only globals at import time).
- Sensitive headers are **omitted entirely** (not echoed, not stored, names absent). Case-insensitive. Omit set: `cookie`, `set-cookie`, `authorization`, `proxy-authorization`, `cf-access-jwt-assertion`, `cf-access-authenticated-user-email`. `x-forwarded-for` is **kept**.
- Every echoed value is HTML-escaped (`&` `<` `>` `"` `'`). JSON path uses `JSON.stringify` + `application/json`.
- Response headers on every response: `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`. HTML responses also set `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:`.
- Errors never leak internals: top-level try/catch → generic `500` body `Internal error`. D1 insert isolated in its own try/catch, swallowed.
- Only `GET`/`HEAD`; other methods → `405`.
- Palette tokens (verbatim from `index.html`): `--bg:#0E1116; --panel:#161A22; --panel-high:#1F2530; --line:#2A323F; --text:#E8EBF0; --muted:#8A93A3; --bronze:#D49A5C; --bronze-bright:#F2C58A`.

---

## File Structure

- Create: `functions/_lib.js` — pure functions: `escapeHtml`, `redactHeaders`, `headersToObject`, `extractFields`, `renderJson`, `renderHtml`, plus the `SENSITIVE_HEADERS` set. (`_`-prefixed so Pages does **not** route it as an endpoint.)
- Create: `functions/ip.js` — the `onRequestGet`/`onRequestHead` handler (thin glue). Imports from `./_lib.js`.
- Create: `schema.sql` — D1 `visits` table + indexes.
- Create: `wrangler.toml` — D1 binding `env.DB`.
- Create: `test/ip.test.js` — `node:test` unit tests for `_lib.js`.
- Modify: `README.md` — add `/ip` section (what it does, schema, how to query D1).

---

### Task 1: Pure lib — `escapeHtml` + `SENSITIVE_HEADERS` + `redactHeaders` + `headersToObject`

**Files:**
- Create: `functions/_lib.js`
- Test: `test/ip.test.js`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `escapeHtml(value: string) => string` — escapes `& < > " '`. Non-strings coerced via `String(value)`; `null`/`undefined` → `""`.
  - `SENSITIVE_HEADERS: Set<string>` — lowercase header names to omit.
  - `headersToObject(headers: Headers) => Record<string,string>` — lowercases keys, preserves values.
  - `redactHeaders(obj: Record<string,string>) => Record<string,string>` — returns a new object with any key in `SENSITIVE_HEADERS` (case-insensitive) removed.

- [ ] **Step 1: Write the failing test**

Create `test/ip.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  escapeHtml,
  SENSITIVE_HEADERS,
  headersToObject,
  redactHeaders,
} from '../functions/_lib.js';

test('escapeHtml leaves a plain string unchanged', () => {
  assert.equal(escapeHtml('curl/8.7.1'), 'curl/8.7.1');
});

test('escapeHtml escapes all five HTML-significant characters', () => {
  assert.equal(
    escapeHtml(`<script>"a"&'b'</script>`),
    '&lt;script&gt;&quot;a&quot;&amp;&#39;b&#39;&lt;/script&gt;',
  );
});

test('escapeHtml escapes & exactly once (no double-encoding)', () => {
  assert.equal(escapeHtml('a & b'), 'a &amp; b');
});

test('escapeHtml maps null/undefined to empty string', () => {
  assert.equal(escapeHtml(null), '');
  assert.equal(escapeHtml(undefined), '');
});

test('headersToObject lowercases keys and preserves values', () => {
  const h = new Headers({ 'User-Agent': 'curl/8.7.1', 'Accept': '*/*' });
  assert.deepEqual(headersToObject(h), {
    'user-agent': 'curl/8.7.1',
    accept: '*/*',
  });
});

test('redactHeaders drops sensitive headers case-insensitively', () => {
  const input = {
    'user-agent': 'curl/8.7.1',
    cookie: 'session=abc',
    authorization: 'Bearer xyz',
  };
  const out = redactHeaders(input);
  assert.deepEqual(out, { 'user-agent': 'curl/8.7.1' });
  assert.equal('cookie' in out, false);
  assert.equal('authorization' in out, false);
});

test('redactHeaders keeps x-forwarded-for', () => {
  const out = redactHeaders({ 'x-forwarded-for': '203.0.113.7' });
  assert.deepEqual(out, { 'x-forwarded-for': '203.0.113.7' });
});

test('SENSITIVE_HEADERS contains the documented omit set', () => {
  for (const name of [
    'cookie', 'set-cookie', 'authorization', 'proxy-authorization',
    'cf-access-jwt-assertion', 'cf-access-authenticated-user-email',
  ]) {
    assert.equal(SENSITIVE_HEADERS.has(name), true, name);
  }
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/ip.test.js`
Expected: FAIL — cannot find module `../functions/_lib.js` (or import errors).

- [ ] **Step 3: Write minimal implementation**

Create `functions/_lib.js`:

```js
// Pure, Worker-independent helpers for the /ip endpoint.
// Importable directly by node:test — no Workers-only globals at import time.

const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

/** Escape the five HTML-significant characters. null/undefined → "". */
export function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (c) => HTML_ESCAPES[c]);
}

/** Header names (lowercase) omitted entirely from echo and storage. */
export const SENSITIVE_HEADERS = new Set([
  'cookie',
  'set-cookie',
  'authorization',
  'proxy-authorization',
  'cf-access-jwt-assertion',
  'cf-access-authenticated-user-email',
]);

/** Convert a Headers instance to a plain object with lowercased keys. */
export function headersToObject(headers) {
  const out = {};
  for (const [key, value] of headers) out[key.toLowerCase()] = value;
  return out;
}

/** Return a new header object with sensitive headers removed (case-insensitive). */
export function redactHeaders(obj) {
  const out = {};
  for (const [key, value] of Object.entries(obj)) {
    if (SENSITIVE_HEADERS.has(key.toLowerCase())) continue;
    out[key] = value;
  }
  return out;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/ip.test.js`
Expected: PASS (all tests in this file so far).

- [ ] **Step 5: Commit**

```bash
git add functions/_lib.js test/ip.test.js
git commit -m "feat: add escapeHtml + header redaction helpers for /ip"
```

---

### Task 2: Pure lib — `extractFields`

**Files:**
- Modify: `functions/_lib.js`
- Test: `test/ip.test.js`

**Interfaces:**
- Consumes: `headersToObject`, `redactHeaders` (Task 1).
- Produces:
  - `extractFields(request) => object` — flat record with keys: `ts, ip, country, city, asn, colo, method, path, http_ver, user_agent, referer, accept_lang, tls_version, tls_cipher, headers`. `request` is a Fetch `Request` with an optional `cf` property. `headers` is the **redacted** header object. Missing `cf`/header values become `null`. `ts` is `new Date().toISOString()`. `ip` comes from the `cf-connecting-ip` header. `path` is the URL pathname.

- [ ] **Step 1: Write the failing test**

Append to `test/ip.test.js`:

```js
import { extractFields } from '../functions/_lib.js';

function fakeRequest({ url = 'https://truepositive.dev/ip', method = 'GET', headers = {}, cf = {} } = {}) {
  return { url, method, headers: new Headers(headers), cf };
}

test('extractFields pulls IP from cf-connecting-ip and path from URL', () => {
  const f = extractFields(fakeRequest({
    headers: { 'cf-connecting-ip': '203.0.113.7', 'user-agent': 'curl/8.7.1' },
    cf: { country: 'US', city: 'Dallas', asn: 13335, colo: 'DFW',
          httpProtocol: 'HTTP/2', tlsVersion: 'TLSv1.3', tlsCipher: 'AEAD-AES128-GCM-SHA256' },
  }));
  assert.equal(f.ip, '203.0.113.7');
  assert.equal(f.path, '/ip');
  assert.equal(f.method, 'GET');
  assert.equal(f.country, 'US');
  assert.equal(f.asn, 13335);
  assert.equal(f.colo, 'DFW');
  assert.equal(f.http_ver, 'HTTP/2');
  assert.equal(f.tls_version, 'TLSv1.3');
  assert.equal(f.tls_cipher, 'AEAD-AES128-GCM-SHA256');
  assert.equal(f.user_agent, 'curl/8.7.1');
  assert.equal(typeof f.ts, 'string');
  assert.match(f.ts, /^\d{4}-\d{2}-\d{2}T/);
});

test('extractFields defaults missing cf fields to null (no throw)', () => {
  const f = extractFields(fakeRequest({ headers: {}, cf: {} }));
  assert.equal(f.country, null);
  assert.equal(f.asn, null);
  assert.equal(f.tls_version, null);
  assert.equal(f.ip, null);
  assert.equal(f.user_agent, null);
  assert.equal(f.referer, null);
  assert.equal(f.accept_lang, null);
});

test('extractFields redacts sensitive headers in the headers map', () => {
  const f = extractFields(fakeRequest({
    headers: { 'user-agent': 'curl/8.7.1', cookie: 'session=abc', authorization: 'Bearer x' },
  }));
  assert.equal('cookie' in f.headers, false);
  assert.equal('authorization' in f.headers, false);
  assert.equal(f.headers['user-agent'], 'curl/8.7.1');
});

test('extractFields tolerates a request with no cf property', () => {
  const f = extractFields({ url: 'https://truepositive.dev/ip', method: 'GET', headers: new Headers() });
  assert.equal(f.country, null);
  assert.equal(f.path, '/ip');
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/ip.test.js`
Expected: FAIL — `extractFields` is not exported.

- [ ] **Step 3: Write minimal implementation**

Append to `functions/_lib.js`:

```js
/** Read a header, returning null when absent. */
function header(obj, name) {
  return obj[name] ?? null;
}

/** Read a cf property, returning null when absent. */
function cf(request, key) {
  return request.cf && request.cf[key] !== undefined ? request.cf[key] : null;
}

/**
 * Extract the flat field record echoed + logged for a request.
 * Missing cf/header values are null. `headers` is the redacted header map.
 */
export function extractFields(request) {
  const all = headersToObject(request.headers);
  return {
    ts: new Date().toISOString(),
    ip: header(all, 'cf-connecting-ip'),
    country: cf(request, 'country'),
    city: cf(request, 'city'),
    asn: cf(request, 'asn'),
    colo: cf(request, 'colo'),
    method: request.method,
    path: new URL(request.url).pathname,
    http_ver: cf(request, 'httpProtocol'),
    user_agent: header(all, 'user-agent'),
    referer: header(all, 'referer'),
    accept_lang: header(all, 'accept-language'),
    tls_version: cf(request, 'tlsVersion'),
    tls_cipher: cf(request, 'tlsCipher'),
    headers: redactHeaders(all),
  };
}
```

> Note: `new Date().toISOString()` is intentional here — this runs in the Workers runtime at request time, not in a workflow script.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/ip.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add functions/_lib.js test/ip.test.js
git commit -m "feat: add extractFields for /ip request parsing"
```

---

### Task 3: Pure lib — `renderJson` + `renderHtml`

**Files:**
- Modify: `functions/_lib.js`
- Test: `test/ip.test.js`

**Interfaces:**
- Consumes: `escapeHtml` (Task 1), a fields object shaped by `extractFields` (Task 2).
- Produces:
  - `renderJson(fields) => object` — returns `fields` as-is (already JSON-serializable). Present as a named function so the handler stays declarative.
  - `renderHtml(fields) => string` — a complete HTML document string; every interpolated value passes through `escapeHtml`; missing values render as `—`; includes an "All headers" `<details>` block over `fields.headers`.

- [ ] **Step 1: Write the failing test**

Append to `test/ip.test.js`:

```js
import { renderJson, renderHtml } from '../functions/_lib.js';

const SAMPLE = {
  ts: '2026-07-09T12:00:00.000Z', ip: '203.0.113.7', country: 'US', city: 'Dallas',
  asn: 13335, colo: 'DFW', method: 'GET', path: '/ip', http_ver: 'HTTP/2',
  user_agent: 'curl/8.7.1', referer: null, accept_lang: null,
  tls_version: 'TLSv1.3', tls_cipher: 'AEAD-AES128-GCM-SHA256',
  headers: { 'user-agent': 'curl/8.7.1', accept: '*/*' },
};

test('renderJson returns the fields object unchanged', () => {
  assert.deepEqual(renderJson(SAMPLE), SAMPLE);
});

test('renderHtml escapes a malicious User-Agent (no raw <script>)', () => {
  const html = renderHtml({ ...SAMPLE, user_agent: '<script>alert(1)</script>',
    headers: { 'user-agent': '<script>alert(1)</script>' } });
  assert.equal(html.includes('<script>alert(1)</script>'), false);
  assert.equal(html.includes('&lt;script&gt;alert(1)&lt;/script&gt;'), true);
});

test('renderHtml never emits a sensitive header even if one leaks into headers', () => {
  // Defense-in-depth: renderHtml only renders what it is given, but the field
  // pipeline redacts upstream. Verify a benign header shows and the doc is well-formed.
  const html = renderHtml(SAMPLE);
  assert.equal(html.startsWith('<!DOCTYPE html>'), true);
  assert.equal(html.includes('203.0.113.7'), true);
  assert.equal(html.includes('TLSv1.3'), true);
});

test('renderHtml renders missing values as an em dash', () => {
  const html = renderHtml({ ...SAMPLE, referer: null });
  // The Referer row label is present and its value cell shows the dash.
  assert.match(html, /Referer[\s\S]*?—/);
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/ip.test.js`
Expected: FAIL — `renderJson`/`renderHtml` not exported.

- [ ] **Step 3: Write minimal implementation**

Append to `functions/_lib.js`:

```js
export function renderJson(fields) {
  return fields;
}

/** Render one label/value row; value is escaped, null → em dash. */
function row(label, value) {
  const shown = value === null || value === undefined || value === ''
    ? '—'
    : escapeHtml(value);
  return `<tr><th>${escapeHtml(label)}</th><td>${shown}</td></tr>`;
}

/** Render the redacted headers map as escaped <details> rows. */
function headerRows(headers) {
  return Object.entries(headers)
    .map(([k, v]) => `<tr><th>${escapeHtml(k)}</th><td>${escapeHtml(v)}</td></tr>`)
    .join('');
}

/** Full HTML document echoing the request. Every value is escaped. */
export function renderHtml(f) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Your request · True Positive</title>
<link rel="icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' rx='7' fill='%23161A22'/%3E%3Cpath d='M9 16.5l4.5 4.5L23 11' fill='none' stroke='%23D49A5C' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'/%3E%3C/svg%3E">
<style>
:root{--bg:#0E1116;--panel:#161A22;--panel-high:#1F2530;--line:#2A323F;--text:#E8EBF0;--muted:#8A93A3;--bronze:#D49A5C;--bronze-bright:#F2C58A}
*{box-sizing:border-box}html,body{margin:0}
body{background:var(--bg);color:var(--text);font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;-webkit-font-smoothing:antialiased}
main{max-width:720px;margin:0 auto;padding:clamp(2rem,6vw,4rem) 1.5rem 3rem}
h1{font-size:clamp(1.6rem,5vw,2.2rem);letter-spacing:-.02em;margin:0 0 .25rem}
.lede{color:var(--bronze-bright);margin:0 0 2rem}
h2{font-size:.82rem;letter-spacing:.14em;text-transform:uppercase;color:var(--muted);margin:2rem 0 .5rem}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:12px;overflow:hidden}
th,td{text-align:left;padding:.55rem .9rem;vertical-align:top;border-top:1px solid var(--line);font-size:.92rem}
tr:first-child th,tr:first-child td{border-top:none}
th{color:var(--muted);font-weight:500;width:34%;white-space:nowrap}
td{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-word}
details{margin-top:.5rem}summary{cursor:pointer;color:var(--bronze-bright)}
</style>
</head>
<body>
<main>
<h1>Your request</h1>
<p class="lede">Here is what this server sees.</p>
<h2>Your source</h2>
<table>${row('IP', f.ip)}${row('Country', f.country)}${row('City', f.city)}${row('ASN', f.asn)}${row('Colo', f.colo)}</table>
<h2>Request</h2>
<table>${row('Method', f.method)}${row('Path', f.path)}${row('HTTP version', f.http_ver)}${row('User-Agent', f.user_agent)}${row('Referer', f.referer)}${row('Accept-Language', f.accept_lang)}${row('Time (UTC)', f.ts)}</table>
<h2>TLS</h2>
<table>${row('Version', f.tls_version)}${row('Cipher', f.tls_cipher)}</table>
<h2>All headers</h2>
<details><summary>Show ${Object.keys(f.headers).length} headers</summary>
<table>${headerRows(f.headers)}</table>
</details>
</main>
</body>
</html>`;
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/ip.test.js`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add functions/_lib.js test/ip.test.js
git commit -m "feat: add renderJson + renderHtml for /ip"
```

---

### Task 4: The Pages Function handler + D1 schema + wrangler binding

**Files:**
- Create: `functions/ip.js`
- Create: `schema.sql`
- Create: `wrangler.toml`

**Interfaces:**
- Consumes: `extractFields`, `renderJson`, `renderHtml` from `./_lib.js`.
- Produces: HTTP endpoint `GET|HEAD /ip`. No exported JS interface for later tasks.

> This task has no unit test (it's Worker glue + config). It ends with a documented manual verification via `wrangler pages dev`. The pure logic it calls is already covered by Tasks 1–3.

- [ ] **Step 1: Create the D1 schema**

Create `schema.sql`:

```sql
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
```

- [ ] **Step 2: Create the wrangler binding**

Create `wrangler.toml` (replace `database_id` after `wrangler d1 create` in Step 6):

```toml
name = "truepositive"
pages_build_output_dir = "."

[[d1_databases]]
binding = "DB"
database_name = "truepositive"
database_id = "REPLACE_AFTER_d1_create"
```

- [ ] **Step 3: Write the handler**

Create `functions/ip.js`:

```js
import { extractFields, renderJson, renderHtml } from './_lib.js';

const SECURITY_HEADERS = {
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};

const CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:";

/** Best-effort insert; never throws into the response path. */
async function logVisit(env, fields) {
  try {
    if (!env || !env.DB) return;
    await env.DB.prepare(
      `INSERT INTO visits
        (ts, ip, country, city, asn, colo, method, path, http_ver,
         user_agent, referer, accept_lang, tls_version, tls_cipher, headers_json)
       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
    ).bind(
      fields.ts, fields.ip, fields.country, fields.city, fields.asn, fields.colo,
      fields.method, fields.path, fields.http_ver, fields.user_agent,
      fields.referer, fields.accept_lang, fields.tls_version, fields.tls_cipher,
      JSON.stringify(fields.headers),
    ).run();
  } catch (err) {
    // Logging is best-effort; never surface DB errors to the client.
    console.log('visit-log-failed', err && err.message);
  }
}

/** Content-negotiate: browsers (Accept: text/html) get HTML, else JSON. */
function wantsHtml(request) {
  const accept = request.headers.get('accept') || '';
  return accept.includes('text/html');
}

async function handle(context) {
  const { request, env } = context;
  const fields = extractFields(request);
  await logVisit(env, fields);

  if (wantsHtml(request)) {
    return new Response(renderHtml(fields), {
      headers: {
        ...SECURITY_HEADERS,
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': CSP,
      },
    });
  }
  return new Response(JSON.stringify(renderJson(fields), null, 2), {
    headers: { ...SECURITY_HEADERS, 'Content-Type': 'application/json; charset=utf-8' },
  });
}

export async function onRequestGet(context) {
  try {
    return await handle(context);
  } catch (err) {
    console.log('ip-endpoint-error', err && err.message);
    return new Response('Internal error', { status: 500, headers: SECURITY_HEADERS });
  }
}

// HEAD: same headers, no body — reuse GET then strip the body.
export async function onRequestHead(context) {
  const res = await onRequestGet(context);
  return new Response(null, { status: res.status, headers: res.headers });
}

// Any other method → 405.
export function onRequest(context) {
  const m = context.request.method;
  if (m === 'GET') return onRequestGet(context);
  if (m === 'HEAD') return onRequestHead(context);
  return new Response('Method Not Allowed', {
    status: 405,
    headers: { ...SECURITY_HEADERS, Allow: 'GET, HEAD' },
  });
}
```

- [ ] **Step 4: Verify the existing unit tests still pass**

Run: `node --test test/ip.test.js`
Expected: PASS (unchanged — `_lib.js` untouched this task).

- [ ] **Step 5: Provision D1 locally and verify negotiation (manual)**

Requires `wrangler` (`npx wrangler`). If not authenticated, this step is done by the user; document the commands:

```bash
# One-time: create the DB, then paste database_id into wrangler.toml
npx wrangler d1 create truepositive
# Apply schema to the local dev DB
npx wrangler d1 execute truepositive --local --file schema.sql
# Serve Pages + Functions locally
npx wrangler pages dev . &
# JSON (default):
curl -s http://localhost:8788/ip
# HTML (browser Accept):
curl -s -H 'Accept: text/html' http://localhost:8788/ip | head -20
# 405:
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8788/ip   # → 405
```

Expected: JSON body with `ip`/`headers`; HTML body starting `<!DOCTYPE html>`; POST returns `405`.

- [ ] **Step 6: Commit**

```bash
git add functions/ip.js schema.sql wrangler.toml
git commit -m "feat: add /ip Pages Function with D1 logging"
```

---

### Task 5: Docs — README `/ip` section

**Files:**
- Modify: `README.md`

**Interfaces:** none.

- [ ] **Step 1: Add the section**

Append to `README.md`:

```markdown
## /ip request-echo endpoint

`GET /ip` echoes the visitor's request/source info and logs each visit to
Cloudflare D1. It is content-negotiated:

- Browser (`Accept: text/html`) → a styled page.
- `curl truepositive.dev/ip` → JSON.

Sensitive headers (`cookie`, `authorization`, `cf-access-*`, …) are omitted
entirely — never echoed, never stored. Responses are `no-store` and carry a
strict CSP.

### Data

Implemented by `functions/ip.js` (+ pure helpers in `functions/_lib.js`).
Visits are written to the D1 `visits` table (`schema.sql`), bound as `DB` in
`wrangler.toml`.

Query recent visits:

    npx wrangler d1 execute truepositive \
      --command "SELECT ts, ip, country, user_agent FROM visits ORDER BY ts DESC LIMIT 20"

### Local development

    npx wrangler d1 create truepositive          # once; paste id into wrangler.toml
    npx wrangler d1 execute truepositive --local --file schema.sql
    npx wrangler pages dev .

### Tests

    node --test test/ip.test.js
```

- [ ] **Step 2: Commit**

```bash
git add README.md
git commit -m "docs: document /ip endpoint, D1 schema, and querying"
```

---

## Self-Review

**Spec coverage:**
- Content-negotiated `GET /ip` → Task 4 (`wantsHtml`, `onRequest`). ✓
- D1 logging (all columns + `headers_json`) → Task 4 (`logVisit`, `schema.sql`). ✓
- Echo everything, Bell-Bronze HTML → Task 3 (`renderHtml`). ✓
- JSON for curl → Task 3/4 (`renderJson`). ✓
- HTML escaping → Task 1 (`escapeHtml`), verified in Task 3. ✓
- Sensitive headers omitted entirely → Task 1 (`redactHeaders`/`SENSITIVE_HEADERS`), used in Task 2. ✓
- Isolated best-effort D1 write, generic 500 → Task 4 (`logVisit` try/catch, `onRequestGet` try/catch). ✓
- CSP + nosniff + no-store → Task 4 (`SECURITY_HEADERS`, `CSP`). ✓
- 405 for other methods → Task 4 (`onRequest`). ✓
- Missing cf fields → null, no crash → Task 2 (tested). ✓
- Pure functions unit-tested with adversarial cases → Tasks 1–3. ✓
- README/schema/query docs → Task 5. ✓

**Placeholder scan:** `database_id = "REPLACE_AFTER_d1_create"` is an intentional, documented user step (can't be known until `wrangler d1 create` runs), not a plan gap. No other placeholders.

**Type consistency:** `escapeHtml`, `redactHeaders`, `headersToObject`, `extractFields`, `renderJson`, `renderHtml`, `SENSITIVE_HEADERS` are named identically across definition (Tasks 1–3) and use (Tasks 2–4). Field-object keys (`ts, ip, country, city, asn, colo, method, path, http_ver, user_agent, referer, accept_lang, tls_version, tls_cipher, headers`) match between `extractFields`, `renderHtml`, the `INSERT` bind order, and `schema.sql` columns (with `headers` → `headers_json`). ✓
