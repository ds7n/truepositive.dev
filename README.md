# truepositive.dev

Static one-page site for True Positive LLC. Plain HTML/CSS, no build step, no
dependencies, no tracking.

## Deploy

Hosted on Cloudflare Pages (DNS is already on Cloudflare). Pushing to the
default branch triggers a deploy; `truepositive.dev` + `www` are attached as
custom domains in the Pages project.

To preview locally, open `index.html` in a browser (or `python3 -m http.server`).

### Deploy checklist

The static pages deploy on push with no extra steps. The `/ip` endpoint needs
its D1 database in sync — run this when the `visits` schema changes (or on first
setup). All commands run from the repo root with `CLOUDFLARE_API_TOKEN` in
`.env` (see Provisioning below).

1. **Merge to `main` and pull** so you apply the current schema:

       git checkout main && git pull

2. **Apply the schema to the production DB.** `schema.sql` begins with
   `DROP TABLE IF EXISTS visits`, so this **drops and recreates** the table
   (existing rows are lost):

       npx wrangler d1 execute truepositive --remote --file schema.sql

   Verify the column count matches `schema.sql`:

       npx wrangler d1 execute truepositive --remote \
         --command "SELECT COUNT(*) AS cols FROM pragma_table_info('visits')"

3. **Confirm the Pages D1 binding exists** (one-time; git-push deploys do NOT
   read `wrangler.toml` bindings). Dashboard → Workers & Pages → `truepositive`
   → Settings → Functions → D1 database bindings → variable `DB` →
   database `truepositive`. Without it, `/ip` echoes but logs nothing.

4. **Smoke-test logging** after deploy:

       curl -s https://truepositive.dev/ip > /dev/null
       npx wrangler d1 execute truepositive --remote \
         --command "SELECT ts, ip, city, as_org, ua_browser FROM visits ORDER BY ts DESC LIMIT 1"

Steps 2 and 3 are independent and order doesn't matter — the insert no-ops
safely until both the table and the binding exist, so `/ip` never breaks.

## /ip request-echo endpoint

`GET /ip` echoes the visitor's request/source info and logs each visit to
Cloudflare D1. It reports IP, full Cloudflare geolocation (city, region, postal,
timezone, coordinates, ASN + network name), a best-effort User-Agent parse
(browser, OS, device, engine, bot) alongside the raw UA, the request line, TLS
details, and the redacted header set.

Response format:

- Browser (`Accept: text/html`) → a styled page.
- `curl truepositive.dev/ip` → JSON.
- `truepositive.dev/ip/json` or `truepositive.dev/ip?format=json` → JSON from a
  browser too.

Sensitive headers (`cookie`, `authorization`, `cf-access-*`, …) are omitted
entirely — never echoed, never stored. Responses are `no-store` and carry a
strict CSP.

### Data

Implemented by `functions/ip.js` (+ pure helpers in `functions/_lib.js`).
Visits are written to the D1 `visits` table (`schema.sql`), bound as `DB` in
`wrangler.toml`.

Query recent visits (`--remote` targets the production DB):

    npx wrangler d1 execute truepositive --remote \
      --command "SELECT ts, ip, city, region_code, country, as_org, ua_browser, ua_os FROM visits ORDER BY ts DESC LIMIT 20"

The `visits` schema changed when geo/UA columns were added; re-applying
`schema.sql` **drops and recreates** the table (see the `DROP TABLE` at the top),
so run it again after pulling this change:

    npx wrangler d1 execute truepositive --remote --file schema.sql

### Provisioning (one-time)

`wrangler` needs Node ≥ 22. On a headless / SSH box the browser `wrangler login`
flow can't complete (it redirects to `localhost`), so authenticate with an API
token instead.

1. **Create an API token** — Cloudflare dashboard → My Profile → API Tokens →
   Create Custom Token. One permission is enough: **Account · D1 · Edit**,
   scoped to your account. (No zone/Pages permission needed for D1.)

2. **Give it to wrangler via `.env`** (git-ignored — never commit it). In the
   repo root:

       # .env
       CLOUDFLARE_API_TOKEN=your_token_here

   wrangler auto-loads `.env` from the working directory; no `export` needed.

3. **Create the database and apply the schema:**

       npx wrangler d1 create truepositive          # prints database_id
       # → paste database_id into wrangler.toml (replaces the placeholder), commit
       npx wrangler d1 execute truepositive --remote --file schema.sql

   Verify: `npx wrangler d1 execute truepositive --remote \
   --command "SELECT name FROM sqlite_master WHERE type='table'"` → lists `visits`.

4. **Bind the database in the Pages project** (this is what wires `env.DB` for
   git-push deploys — `wrangler.toml` bindings only apply to `wrangler deploy`):
   dashboard → Workers & Pages → **truepositive** → Settings → Functions →
   D1 database bindings → Add: variable `DB` → database `truepositive`.

Until step 4 is done, `/ip` still serves correctly but skips logging — the
insert is guarded and no-ops when `env.DB` is unbound.

### Local development

    npx wrangler d1 execute truepositive --local --file schema.sql   # seeds a local DB
    npx wrangler pages dev .                                          # serves /ip locally

### Tests

    node --test test/ip.test.js
