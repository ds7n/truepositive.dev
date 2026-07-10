# truepositive.dev

Static one-page site for True Positive LLC. Plain HTML/CSS, no build step, no
dependencies, no tracking.

## Deploy

Hosted on Cloudflare Pages (DNS is already on Cloudflare). Pushing to the
default branch triggers a deploy; `truepositive.dev` + `www` are attached as
custom domains in the Pages project.

To preview locally, open `index.html` in a browser (or `python3 -m http.server`).

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
