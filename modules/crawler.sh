#!/usr/bin/env bash
# Crawl authorized seed URLs and retain potentially useful client assets.
set -Eeuo pipefail
BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
source "$BASE_DIR/modules/utils.sh"
INPUT="${1:?Input URL file or URL required}"; OUT="$OUTPUT_DIR/assets/crawled_urls.txt"
VERBOSE="${VERBOSE:-0}"
# Depth comes from config, but JSINTEL_DEPTH overrides it (handy for large
# multi-host scopes where the configured default would be prohibitively deep).
DEPTH="${JSINTEL_DEPTH:-$(awk '/^crawler:/ {p=1; next} p && /^[[:space:]]+depth:/ {print $2; exit}' "$CONFIG" 2>/dev/null || true)}"; DEPTH="${DEPTH:-5}"

host_of() { printf '%s\n' "$1" | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##'; }

RAWSEEDS=$(mktemp); SEEDS=$(mktemp); trap 'rm -f "$RAWSEEDS" "$SEEDS"' EXIT
if [[ -f "$INPUT" ]]; then grep -E '^https?://' "$INPUT" | sed 's/\r$//' > "$RAWSEEDS" || true; else printf '%s\n' "$INPUT" > "$RAWSEEDS"; fi
[[ -s "$RAWSEEDS" ]] || die "No valid http(s) seed URLs in: $INPUT"

# --- Crawl scope --------------------------------------------------------------
# katana's JS link-extraction (-jsl) also emits URLs *referenced inside* JS, which
# for a real site includes third-party hosts (analytics, social, CDNs). Fetching
# those is out of an authorized-scope assessment, so discovered assets are
# constrained to a set of registered domains. When CRAWL_SCOPE is set (jsintel.sh
# passes the AUTHORIZED -s/-p/-f scope), that set is the authorization anchor and
# is computed *before* redirect resolution so an off-scope redirect can never widen
# it; CRAWL_SCOPE=off disables filtering; otherwise the scope is derived from the
# (post-redirect) seed hosts. This is a security control: an authorized gala.com
# test must not start crawling okta.com just because a gala.com host redirects there.
reg_dom() { awk -F. '{n=NF; if(n>=2) print tolower($(n-1)"."$n); else print tolower($0)}'; }
SCOPE_DOMS=$(mktemp); trap 'rm -f "$RAWSEEDS" "$SEEDS" "$SCOPE_DOMS"' EXIT
ANCHORED=0
if [[ "${CRAWL_SCOPE:-}" == "off" ]]; then
  : > "$SCOPE_DOMS"
elif [[ -n "${CRAWL_SCOPE:-}" ]]; then
  # shellcheck disable=SC2086
  printf '%s\n' ${CRAWL_SCOPE//,/ } | sed -E 's#^[a-zA-Z]+://##; s#/.*$##; s#:.*$##' | tr 'A-Z' 'a-z' | grep -E '\.' | sort -u > "$SCOPE_DOMS"
  ANCHORED=1
else
  : > "$SCOPE_DOMS"   # derived from post-redirect seeds after the loop below
fi

# host_in_scope <host>: true if host equals or is a subdomain of a SCOPE_DOMS entry.
declare -A SCOPE_SET=()
while IFS= read -r d; do [[ -n "$d" ]] && SCOPE_SET["$d"]=1; done < "$SCOPE_DOMS"
host_in_scope() {
  local host suffix="" i; host="$(printf '%s' "$1" | tr 'A-Z' 'a-z')"
  local IFS='.'; read -r -a _parts <<<"$host"
  for ((i=${#_parts[@]}-1; i>=0; i--)); do
    suffix="${_parts[i]}${suffix:+.$suffix}"
    [[ -n "${SCOPE_SET[$suffix]:-}" ]] && return 0
  done
  return 1
}

# Resolve redirects so a seed that 301s to a *different* host (e.g. gala.games ->
# games.gala.com) is crawled at its real location. katana scopes crawling to the
# seed's host, so feeding it the pre-redirect URL silently yields zero assets. When
# a scope is anchored, a redirect that leaves it is NOT followed: we keep the
# in-scope seed if possible, otherwise drop it -- never crawling the off-scope host.
if command -v curl >/dev/null 2>&1; then
  # Carry the operator-supplied session into redirect resolution: without it, an
  # authenticated app's seed (e.g. /index.php) 302s to /login.php and the crawl
  # silently falls back to the unauthenticated view.
  CURL_AUTH=()
  [[ -n "${JSINTEL_AUTH_COOKIE:-}" ]] && CURL_AUTH+=(-H "Cookie: ${JSINTEL_AUTH_COOKIE}")
  [[ -n "${JSINTEL_AUTH_BEARER:-}" ]] && CURL_AUTH+=(-H "Authorization: Bearer ${JSINTEL_AUTH_BEARER}")
  while IFS= read -r seed; do
    [[ -n "$seed" ]] || continue
    eff=$(curl -sS -L -o /dev/null -w '%{url_effective}' --max-time 20 ${CURL_AUTH[@]+"${CURL_AUTH[@]}"} "$seed" 2>/dev/null || true)
    if [[ -n "$eff" && "$eff" != "$seed" && "$(host_of "$eff")" != "$(host_of "$seed")" ]]; then
      if [[ "$ANCHORED" == "1" ]] && ! host_in_scope "$(host_of "$eff")"; then
        if host_in_scope "$(host_of "$seed")"; then
          log_warn "Seed $seed redirects off-scope to $eff — NOT following; crawling $seed in-scope"
          printf '%s\n' "$seed" >> "$SEEDS"
        else
          log_warn "Seed $seed redirects off-scope to $eff and is itself out of scope — dropping"
        fi
      else
        log_warn "Seed $seed redirects off-host to $eff — crawling the redirect target"
        printf '%s\n' "$eff" >> "$SEEDS"
      fi
    elif [[ -n "$eff" && "$eff" != "$seed" ]]; then
      [[ "$VERBOSE" == "1" ]] && log_info "Seed $seed resolved to $eff"
      printf '%s\n' "$eff" >> "$SEEDS"
    else
      printf '%s\n' "$seed" >> "$SEEDS"
    fi
  done < "$RAWSEEDS"
  sort -u "$SEEDS" -o "$SEEDS"
else
  [[ "$VERBOSE" == "1" ]] && log_warn "curl not found; skipping redirect resolution"
  cp "$RAWSEEDS" "$SEEDS"
fi
[[ -s "$SEEDS" ]] || die "No resolvable in-scope seed URLs from: $INPUT"

ASSET_RE='\.(js|mjs|map|json|wasm)([?#].*)?$|(^|[/._-])(service-)?worker([._/?#-]|$)|manifest(\.json|\.webmanifest)?([?#].*)?$'
# Server-rendered PAGES (PHP, JSP/Java, ASP.NET, ColdFusion, CGI/Perl/Python/Ruby),
# static HTML, and extensionless "routes" (Flask/Express/etc. and directory paths).
# Kept in addition to JS assets so the pipeline can crawl and analyze non-JS stacks.
# Toggle off with JSINTEL_CRAWL_PAGES=0 for the classic JS-only behavior.
PAGE_RE='\.(php|phtml|php[0-9]|html?|xhtml|shtml|asp|aspx|ashx|jsp|jspx|do|action|cfm|cgi|pl|py|rb)([?#].*)?$|/([?#].*)?$|://[^/]+/[^./?#]+([?#].*)?$'
if [[ "${JSINTEL_CRAWL_PAGES:-1}" != "0" ]]; then
  CRAWL_RE="$ASSET_RE|$PAGE_RE"
else
  CRAWL_RE="$ASSET_RE"
fi

# Default (unanchored) scope: derive registered domains from the post-redirect seeds.
if [[ "$ANCHORED" == "0" && "${CRAWL_SCOPE:-}" != "off" ]]; then
  while IFS= read -r seed; do [[ -n "$seed" ]] && host_of "$seed"; done < "$SEEDS" | reg_dom | grep -E '\.' | sort -u > "$SCOPE_DOMS"
fi
[[ -s "$SCOPE_DOMS" ]] && log_info "Crawl scope (registered domains): $(paste -sd' ' "$SCOPE_DOMS")"

# Clean katana output (unescape JS backslash-escapes, drop malformed URLs), keep
# only asset-like URLs, and restrict to the crawl scope when one is set.
clean_and_scope() {
  sed -e 's#\\/#/#g' \
    | grep -Eiv '\\|%5[Cc]' \
    | grep -Ei "$CRAWL_RE" \
    | sed 's/[[:space:]]*$//' \
    | if [[ -s "$SCOPE_DOMS" ]]; then
        awk -v sf="$SCOPE_DOMS" '
          BEGIN { while ((getline d < sf) > 0) if (d != "") scope[d]=1 }
          { url=$0; h=url; sub(/^[a-zA-Z]+:\/\//,"",h); sub(/[\/?#].*$/,"",h); sub(/.*@/,"",h); sub(/:[0-9]+$/,"",h); h=tolower(h);
            keep=0; n=split(h,p,"."); suf="";
            for (i=n; i>=1; i--) { suf=(suf==""?p[i]:p[i]"."suf); if (suf in scope) { keep=1; break } }
            if (keep) print url }'
      else cat; fi \
    | sort -u
}

if command -v katana >/dev/null 2>&1; then
  log_info "Crawling with katana (depth $DEPTH)"
  # Authenticated crawl: forward the operator-supplied session (--cookie/--jwt) as
  # request headers so pages behind login are crawled. Scope is still anchored.
  KATANA_AUTH=()
  [[ -n "${JSINTEL_AUTH_COOKIE:-}" ]] && KATANA_AUTH+=(-H "Cookie: ${JSINTEL_AUTH_COOKIE}")
  [[ -n "${JSINTEL_AUTH_BEARER:-}" ]] && KATANA_AUTH+=(-H "Authorization: Bearer ${JSINTEL_AUTH_BEARER}")
  # When authenticated, never crawl logout/sign-out links -- following one would
  # destroy the supplied session and the rest of the crawl would fall back to the
  # unauthenticated view. -cos is katana's out-of-scope (exclude) regex.
  if [[ ${#KATANA_AUTH[@]} -gt 0 ]]; then
    KATANA_AUTH+=(-cos "${JSINTEL_LOGOUT_RE:-logout|logoff|signout|sign-out|sign_out|/exit|destroy_session}")
  fi
  RAWCRAWL=$(mktemp); trap 'rm -f "$RAWSEEDS" "$SEEDS" "$SCOPE_DOMS" "$RAWCRAWL"' EXIT
  # Always run katana the same way -- clean URL list on stdout via -silent -- so
  # crawling stays on one reliable, fast code path. Two earlier verbose designs
  # broke here: the decorated `-v` output piped through tee/grep could hang on
  # katana's headless path, and both `tee ... >&2` and a `2> >(tee ...)` process
  # substitution left RAWCRAWL empty (URL stream misrouted, or the proc-sub hung
  # under `set -o pipefail`), so every verbose crawl found zero assets. Verbose
  # therefore does NOT change how katana runs; it only adds logging around it.
  [[ "$VERBOSE" == "1" ]] && log_info "Verbose crawl of: $(paste -sd' ' "$SEEDS")"
  # Redirect stdin from /dev/null: with `-list <file>` katana still reads stdin and,
  # when stdin is an open pipe with no EOF (CI/cron/pipeline/non-interactive shells),
  # it blocks forever. Closing stdin keeps the crawl from hanging.
  katana -list "$SEEDS" -d "$DEPTH" -jc -jsl -silent -c "$THREADS" ${KATANA_AUTH[@]+"${KATANA_AUTH[@]}"} </dev/null 2>>"$LOG_FILE" > "$RAWCRAWL" || true
  clean_and_scope < "$RAWCRAWL" > "$OUT" || true
  if [[ "$VERBOSE" == "1" ]]; then
    log_info "Crawler saw $(wc -l < "$RAWCRAWL" | tr -d ' ') total URLs before asset filtering"
    # Surface exactly what katana discovered (silent mode is quiet on stderr), so
    # an empty or off-scope crawl is diagnosable without opening the log file.
    sed 's/^/  crawled: /' "$RAWCRAWL" >&2 || true
  fi
else
  log_warn "katana is unavailable; treating input URLs as discovered assets"
  cp "$SEEDS" "$OUT"
fi

COUNT=$(wc -l < "$OUT" | tr -d ' ')
log_info "Crawler discovered $COUNT candidate assets"
if [[ "$COUNT" == "0" ]]; then
  log_warn "No assets found. Check that seeds are in scope and reachable, that the target's JS ends in .js/.mjs/.map/.json/.wasm, and re-run with -v to see katana's output."
fi
