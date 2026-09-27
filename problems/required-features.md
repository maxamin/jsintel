# Required features (from false negatives)

Backlog derived from `problems.md`. Shipped items move to `TESTING_PROGRESS.md`.

## Shipped
- ✅ **Source-map un-minification** — recover `sourcesContent`, re-scan with the full
  secret ruleset + URL/API regexes (`sourcemap_analyzer.py`).
- ✅ **Source-map discovery** — derive `<bundle>.map` for every JS asset
  (`JSINTEL_MAP_DISCOVERY`).
- ✅ **Exposed API spec/docs/IDE detector** — `liveanalysis.py` flags reachable
  `/openapi.json`, `/swagger.json`, `/docs`, `/ui/`, GraphiQL, … (medium).
- ✅ **API-spec → endpoints ingestion** — a parsed OpenAPI/Swagger spec's `paths`
  are harvested as endpoints (attributed to the service, ingested by the DB).
  Verified: VAmPI's `/openapi.json` yields 12 endpoints incl. `/users/v1/_debug`.
- ✅ **Injectable-parameter candidates** — query params named
  `id|page|file|path|url|redirect|cmd|q|search|include|…` → `reflected_param_candidate`
  (low). Verified: DVWA yields 8.
- ✅ **Missing-CSRF-token forms** — POST forms with no anti-CSRF hidden field →
  `form_without_csrf_token` (low). Correctly quiet on DVWA (it uses `user_token`).
- ✅ **Framework debug-page / verbose-error detection** — Werkzeug/Flask debugger,
  Django DEBUG, stack traces, Spring error page → `debug_page_exposed` (high).
- ✅ **Sensitive-file exposure** — `/.git/config`, `/.git/HEAD`, `/.env`, `/.htpasswd`,
  `*.bak`, `phpinfo.php`, `server-status` → `sensitive_file_exposed` (severity by
  class). Guarded against soft-404/login-catch-all HTML (no-redirect fetch +
  HTML-body rejection for plaintext secrets). Verified: DVWA's `.git` exposure caught.

## Open
- ✅ **Cloud-bucket references** — `cloud_analyzer.py` (S3/GCS/Azure/DO Spaces).
- **Native launchers for Apache+MySQL PHP labs** (bWAPP/Mutillidae) or a documented
  "requires real Docker host" path — see `problems.md` (multi-service, PHP-8.4).
- **NodeGoat with native loopback MongoDB** to add an Express/Mongo target.
