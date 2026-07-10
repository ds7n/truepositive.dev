# Design: `/ip` request-echo + logging endpoint

**Date:** 2026-07-09
**Status:** Approved (pending spec review)

## Summary

Add a single Cloudflare Pages Function at `functions/ip.js` serving `GET /ip`
(and `HEAD`). It echoes the visitor's request/source information back to them
and logs each visit to a Cloudflare D1 database for later querying. The response
is **content-negotiated**: browsers (`Accept: text/html`) get a styled HTML page
in the site's Bell-Bronze palette; everything else (e.g. `curl`) gets JSON.

This preserves the site's existing model: no build step, no client-side JS
required, same git-push-to-Cloudflare-Pages deploy.

## Goals

- Show a visitor their own IP, geo/source, HTTP request, and TLS details.
- Be `curl`-friendly (`curl truepositive.dev/ip` returns JSON).
- Persist each visit to a durable, SQL-queryable store (D1) the operator owns.
- Leak nothing on the error path; be safe against reflected-input (XSS) and
  sensitive-header exposure.

## Non-goals

- No analytics dashboard/UI over the data (query via `wrangler`/D1 API).
- No rate limiting or abuse controls in v1 (Cloudflare sits in front).
- No JA3/JA4 TLS fingerprinting (not reliably present in `request.cf` on Pages).

## Architecture

```
GET /ip
  → functions/ip.js  (Cloudflare Pages Function, Workers runtime)
      1. extract fields from request.headers + request.cf
      2. INSERT one row into D1 (env.DB)   [isolated, best-effort]
      3. content-negotiate on Accept:
           text/html  → styled HTML page (fields server-rendered)
           otherwise  → application/json
```

- **Binding:** D1 database bound as `env.DB` via `wrangler.toml`
  (`[[d1_databases]]`).
- **No client JS.** All fields are server-rendered into the HTML.
- **One round-trip.** Logging always happens on the same request that echoes.

### Testable decomposition

The leak-prone and data-shaping logic is factored into **pure functions** so it
can be unit-tested without a live Worker:

- `extractFields(request)` → a plain object of all fields (from headers + `cf`).
- `redactHeaders(headersObject)` → header map with sensitive headers **omitted**.
- `escapeHtml(string)` → HTML-entity-escaped string.
- `renderHtml(fields)` → the full HTML document string.
- `renderJson(fields)` → the JSON-serializable object.

The Function's `onRequest` handler is thin glue: call `extractFields`, attempt
the D1 insert, negotiate, and return.

## Data model (D1)

Single table `visits`. Columns are broken out for querying; `headers_json`
retains the full (redacted) header set so nothing useful is lost.

```sql
CREATE TABLE visits (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  ts            TEXT NOT NULL,          -- ISO-8601 UTC, Function-generated
  -- core network
  ip            TEXT,                   -- CF-Connecting-IP
  country       TEXT,                   -- request.cf.country
  city          TEXT,                   -- request.cf.city
  asn           INTEGER,                -- request.cf.asn
  colo          TEXT,                   -- request.cf.colo (CF datacenter)
  -- HTTP request
  method        TEXT,
  path          TEXT,
  http_ver      TEXT,                   -- request.cf.httpProtocol
  user_agent    TEXT,
  referer       TEXT,
  accept_lang   TEXT,
  -- TLS / connection
  tls_version   TEXT,                   -- request.cf.tlsVersion
  tls_cipher    TEXT,                   -- request.cf.tlsCipher
  -- catch-all (redacted headers only)
  headers_json  TEXT                    -- full header set as JSON, sensitive omitted
);
CREATE INDEX idx_visits_ts ON visits(ts);
CREATE INDEX idx_visits_ip ON visits(ip);
```

Schema lives in `schema.sql`; applied with
`wrangler d1 execute truepositive --file schema.sql`.

## Response shapes

### JSON (default / non-browser)

Flat object mirroring the columns (minus `id`), plus a nested `headers` map:

```json
{
  "ts": "2026-07-09T12:00:00.000Z",
  "ip": "203.0.113.7",
  "country": "US",
  "city": "Dallas",
  "asn": 13335,
  "colo": "DFW",
  "method": "GET",
  "path": "/ip",
  "http_ver": "HTTP/2",
  "user_agent": "curl/8.7.1",
  "referer": null,
  "accept_lang": null,
  "tls_version": "TLSv1.3",
  "tls_cipher": "AEAD-AES128-GCM-SHA256",
  "headers": { "user-agent": "curl/8.7.1", "accept": "*/*" }
}
```

`Content-Type: application/json; charset=utf-8`.

### HTML (browsers)

A page styled to match `index.html` (same palette tokens, header mark, favicon).
Sections:

- **Your source** — IP, country, city, ASN, colo.
- **Request** — method, path, HTTP version, User-Agent, Referer, Accept-Language.
- **TLS** — version, cipher.
- **All headers** — a `<details>` block listing the redacted header set.

Missing fields render as `—`. `Content-Type: text/html; charset=utf-8`.

## Security & error handling

The design has two independent paths; **failure in either never reveals
internals**.

- **Top-level try/catch.** Any unhandled error → generic `500` with a fixed body
  (`Internal error`). The exception object is never serialized into the response.
- **D1 write isolated.** The `INSERT` runs in its own inner try/catch that
  swallows all errors (optionally `console.log` server-side only). The response
  is computed independently of whether logging succeeded — echo is the
  user-facing contract, logging is best-effort.
- **HTML escaping.** Every echoed value is HTML-entity-escaped (`& < > " '`)
  before interpolation. This is the primary XSS defense (attacker controls
  headers like `User-Agent`, `Referer`). JSON path is inherently safe.
- **Sensitive headers omitted entirely.** A denylist (see below) is dropped
  completely — not echoed, not stored, names do not appear. Nothing sensitive is
  persisted at rest.
- **Response headers (hardening):**
  - `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:`
    — blocks script execution even if an escape is missed.
  - `X-Content-Type-Options: nosniff`
  - `Cache-Control: no-store` — never cache a per-visitor response.
  - No `X-Powered-By` / verbose `Server`; explicit tight header set.
- **Method scope.** `GET`/`HEAD` only; other methods → `405`.
- **Missing `cf` fields** → defensive reads with `null`/`—` defaults, never a
  crash.

### Redaction denylist (v1)

Omitted (case-insensitive match): `cookie`, `set-cookie`, `authorization`,
`proxy-authorization`, `cf-access-jwt-assertion`,
`cf-access-authenticated-user-email`. `x-forwarded-for` is **kept** (useful,
non-secret). Any header matching the omit set is dropped from both echo and
storage.

## Testing

No build/test harness exists in the repo today; add a minimal one (Node's
built-in `node:test`, zero dependencies) targeting the pure functions.

- **`escapeHtml`** — EP + adversarial: plain string unchanged; `<script>` →
  entities; embedded quotes `"` `'` escaped; `&` escaped once (no double-encode).
- **`redactHeaders`** — a `Cookie` header is absent from output; an
  `Authorization` header is absent; a benign `User-Agent` is present; matching is
  case-insensitive (`COOKIE` also dropped).
- **`extractFields`** — given a fake request with headers + `cf`, returns the
  expected flat object; missing `cf` fields become `null` (no throw).
- **`renderHtml`** — a `User-Agent` of `<script>alert(1)</script>` appears
  escaped (no raw `<script>` substring) in the output; a sensitive header never
  appears.
- **Manual/documented checks:**
  - `curl -s truepositive.dev/ip` → JSON.
  - `curl -s -H 'Accept: text/html' truepositive.dev/ip` → HTML.
  - Verify a row lands in D1 after a request.

## Files

- `functions/ip.js` — the Pages Function (thin handler + pure helpers, or helpers
  in a sibling module imported by the function).
- `schema.sql` — D1 table + indexes.
- `wrangler.toml` — D1 binding (`env.DB`).
- `test/ip.test.js` — `node:test` unit tests for the pure functions.
- `README.md` — new section: what `/ip` does, the `visits` schema, and how to
  query it (`wrangler d1 execute …`).

## Deploy / ops notes

- Create the D1 DB once: `wrangler d1 create truepositive`, add the returned
  binding to `wrangler.toml`, apply `schema.sql`.
- Cost: comfortably within Cloudflare free tier (D1 free: 100k writes/day, 5GB;
  Pages Functions free: 100k requests/day). Effectively $0 for this traffic.
- Query later, e.g.:
  `wrangler d1 execute truepositive --command "SELECT ts, ip, country, user_agent FROM visits ORDER BY ts DESC LIMIT 20"`

## Open questions / future

- Rate limiting / abuse controls if the endpoint gets scraped.
- Optional retention policy (periodic delete of old rows) if privacy posture
  calls for it.
- JA3/JA4 fingerprinting if it becomes reliably available on Pages.
