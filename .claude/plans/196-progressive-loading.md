# Issue #196 — Progressive-Loading Re-architecture — PLAN + STATUS

Durable copy of the Fable 5 architecture plan (the scratchpad copy was lost in a
session restart). Web source dir: `web/public_html/`. 7 ordered steps, each lands green.

## STATUS — ✅ ALL STEPS COMPLETE (2026-07-11), code-complete + 149 tests green
All 7 steps implemented. `Step 1` (`aed2e12`) is pushed + CI-green; Steps 3–7 + 2
are **8 local commits on `beta`, unpushed, clean fast-forward.** Remaining: PUSH +
final **browser/visual verification of the progressive UX** (no browser in the build
sandbox — backend fully verified via 149 PHPUnit tests + live `php -S` smoke).

- ✅ **Step 1** — module registry extraction (byte-identical). `aed2e12` (pushed, CI green).
- ✅ **Step 3** — per-module caches. `1cf0aa6`.
- ✅ **Step 4** — module endpoints `?modules=` + rate-exempt `lookup_token`. `2b12736`.
- ✅ **Step 5** — frontend renderer split (slot-based, 45/45 keys). `1554dcb`.
- ✅ **Step 6** — progressive switch-on. `90dbc6b` + fixes `34b549e` (complete core payload: added registrar_reputation/domain_age_risk/whois_privacy/screenshot_url/domain_suggestions/verification_token; fixed subdomains slot race) + `a51766a` (PHP 8.4 session ini_set was corrupting JSON responses). Live-verified: core fields present, clean JSON, back-compat 51 keys.
- ✅ **Step 7** — OpenAPI module API docs (`?modules=`, `lookup_token`, CoreLookupResponse/ModuleResponse/ScoreResponse). `2e3bb24`.
- ✅ **Step 2** — SSRF-safe `curl_multi`: `curlMultiBatch()` helper + 31 SSRF unit tests (caught+fixed a bracketed-IPv6 bypass) `6e7dfe9`; reputation batch `af5c7f4`; dig-batch subdomains `9587560`. Redirect-followers (auditHttpHeaders/detectRedirectChain/detectTechStack) + getSslInfo deliberately LEFT serial on the vetted path (lower risk). Serial fallbacks for no-curl_multi / no-dig.

## Module grouping (transport bundles; frontend renders per RESPONSE KEY, not per module)
- **core** (blocking, <3s): domain,is_ip,availability,data_source,parsed,dns,raw/whois,cached,reverse_dns(IP), registrar_reputation,domain_age_risk,whois_privacy (local), screenshot_url(DNT+config), domain_suggestions([]), verification_token,rate_limit,dnt, + lookup_token, + modules_available[].
- **dns**: dnssec, ipv6, ns_diversity, dns_propagation. No DNT gating. (cache key has NO :dnt suffix)
- **web**: ssl, http_headers(DNT), tls_audit(DNT), http_versions(DNT), redirect_chain(DNT), response_times(DNT), tech_stack(DNT), robots_txt(DNT), cert_transparency(DNT), dane_tlsa, caa_records.
- **email**: email_security, mta_sts, bimi, smtp_security, hibp(DNT+hibp_api_key), multi_dnsbl(first_a), spamhaus(derived).
- **reputation** (fixed 3rd-party APIs; NOT fired by frontend under DNT): safe_browsing/virustotal/phishtank/urlhaus/abuseipdb/shodan(all DNT; keys where noted), geolocation(DNT+first_a_or_ip), hosting_risk(derived from geolocation).
- **subdomains**: subdomains, reverse_ip(DNT+first_a).
- **score**: security_score only, server-computed from module caches.

## Endpoint contract
`POST /lookup?modules=<core|dns|web|email|reputation|subdomains|score>` (ONE per request). Body: domain, csrf_token (unless X-API-Key), lookup_token (optional, rate-exempt), source=whois(core only). Invalid module→400; modules+suggest/dns_propagation_only→400.
- core response = today's shape MINUS 30 enrichment keys, PLUS lookup_token + modules_available. whois(escaped/masked) for UI, raw for format=json/API-key. available→modules_available=[]; IP→['email','reputation'].
- module envelope: {domain, module, status:ok|skipped_available|error, dnt, cached, generated_at, data:{key:val...legacy shapes...}, skipped:{key:reason(dnt|no_api_key|is_ip|blocked_egress)}}. (Per Step-4 impl: NO module-level skipped_dnt — reputation's hosting_risk is unconditional; use per-key skipped reasons instead.) score envelope: data:{security_score, inputs_missing:[]}.

## lookup_token (rate-limit exemption) — IMPLEMENTED
CACHE_DIR/.module_token_key (random_bytes(32), 0600). issueLookupToken($domain,$binding)/validateLookupToken(). HMAC-SHA256 over base64url(json{v,d,b,exp=+180,n}); binding=sha256(session_id()) CSRF | sha256(apiKeyHash) API. ANY validation failure ⇒ fall back to COUNTED rate limiting (never 403). Exempts only the counter; CSRF/API-key still enforced.

## Caching — IMPLEMENTED
raw whois: $domain. full: full:{domain}{:dnt}{:json} — LEGACY only. mod:core:{domain}{:dnt}. mod:{module}:{domain}{:dnt} (dns has NO :dnt). Legacy path warms all mod:* caches. source=whois bypasses read of $domain+mod:core (still writes). security_score not cached.

## security_score = server-side modules=score endpoint. Reads mod:{email,web,dns,reputation} caches, derives spamhaus if needed, calls calculateSecurityScore(), reports inputs_missing.

## Frontend plan (Step 5 + 6) — index.php
- **Step 5 (refactor, no network change):** split monolithic `displayResults()` into slot-based per-key renderers, each writing into a PRE-CREATED placeholder slot so async arrival can't reorder layout. renderCore + per-key: renderGeolocation, renderEmailSecurity, renderDnssec, renderSsl, renderShodan, renderHttpHeaders, renderTlsAudit, renderCaa, renderSmtp, renderRedirectChain, renderHttpVersions, renderIpv6, renderResponseTimes, renderNsDiversity, renderReverseIp, renderSecurityScore, renderTechStack, renderRobots, renderDnsPropagation, renderMultiDnsbl, renderSubdomains, renderSummaryAlert. `displayResults(data)` becomes `renderCore(data)` + `renderModule(each,{data:subset})` called synchronously from the ONE full response. Pane map: parsedFields(summary/score/alerts/geo/redirect/resptimes/timeline), dnsResultPane(dns/dnssec/ipv6/ns_diversity/dns_propagation), emailSecurityPane(email/mta_sts/bimi/hibp/smtp/multi_dnsbl), sslPane(ssl/dane_tlsa/cert_transparency/shodan/http_headers/tls_audit/caa/http_versions), subdomainsPane(reverse_ip/tech_stack/robots/subdomains), securityPane(score). GATE: visual parity, no console errors.
- **Step 6 (switch-on):** postLookup(url,domain,token) shared FormData helper (domain,csrf_token:CSRF,lookup_token?). triggerLookup: lookupGen guard; fetch modules=core→renderCore→saveHistory; if modules_available empty return; else startModuleFetches: renderModuleSkeleton each; fire all module fetches CONCURRENT; renderModule on each (Object.assign(lastLookupData,res.data); fill slots; skipped[key]=='dnt'→muted note; tab spinner); after allSettled([dns,web,email,reputation]) fire modules=score→renderScore. reputation NOT fired if core.dnt (show "Skipped — DNT" note in its summary slot). renderModuleFailed(name): alert + Retry re-fires that module (same token, valid 180s). hideResults resets slots. Bulk→modules=core (uses whois/availability/parsed only). Compare→KEEP legacy full. Refresh&Diff→modules=core&source=whois. dns-prop refresh unchanged. format=json/API→legacy. GATE: manual matrix + rate budget (1 lookup=1/30 counted).

## Step 7 docs: openapi.yaml modules param (enum) + CoreLookupResponse/ModuleResponse/ScoreData schemas + lookup_token (issued+request+exemption+180s TTL); note LookupResponse(full) remains default. docs.php examples. Changelog.

## Risks/defaults: session_write_close() in handleModuleRequest (DONE). Token secret in CACHE_DIR (degrade to counted on loss). lookupGen guard for stale responses. Fire all modules (add JS concurrency pool of 3 only if worker pressure). IP→['email','reputation']. Compare stays legacy. NEEDS OWNER (non-blocking, defaults chosen): Compare progressive columns; whether to promote progressive API publicly.

## Sandbox note: DNS resolver HANGS on DNS_CAA/DNS_TLSA (dns_get_record) → real-domain lookups that hit the web module (checkCaaRecords/checkDaneTlsa) hang. Verify via IP lookups (8.8.8.8), core (google.com works — no CAA/TLSA), unit tests, and reason-through for the web module. Environmental, not a code bug.

## Verify: PHPUnit (registry completeness DONE; token round-trip/expiry/tamper DONE 84 tests). Server smoke (core fast; each module envelope; token exemption; 429; DNT; availability gate; auth 403; invalid 400; back-compat format=json key-identical; source=whois not cached). SSRF regression (127.0.0.1.nip.io blocked) — for Step 2. Frontend matrix (Step 5/6). Latency (core<3s uncached).
