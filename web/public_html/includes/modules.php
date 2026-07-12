<?php
/**
 * mwWhoIs — Module registry + module endpoints (Issue #196)
 *
 * Step 1: moduleRegistry()/runModuleChecks()/deriveSpamhausFromMultiDnsbl()
 * are a pure extraction of the enrichment pipeline that used to live inline
 * in lookup.php's `if ($availability !== 'available') { ... }` block — no
 * behaviour change; the descriptor map reproduces the exact same checks,
 * with the exact same gating (DNT / API key / IP-lookup / first-A-record)
 * the inline code used to apply.
 *
 * Step 3: getModuleCache()/setModuleCache()/moduleCacheKey() — independent
 * per-module response caches, warmed by the legacy full-pipeline path.
 *
 * Step 4: runCoreLookup() (the CORE half of the legacy pipeline — IP branch
 * + domain branch: raw-whois cache, RDAP-first, WHOIS fallback, parsing,
 * DNS — extracted so it can run standalone for a `modules=core` request),
 * the lookup_token HMAC (moduleTokenSecret()/issueLookupToken()/
 * validateLookupToken()/resolveLookupTokenBinding()), and the
 * handleModuleRequest() dispatcher wired into lookup.php behind
 * `?modules=`. Deliberately NOT included: curlMultiBatch() (Step 2,
 * parallelisation — not part of this pass; module checks still run
 * serially within a module).
 *
 * The "core" response keys (domain, is_ip, availability, data_source,
 * parsed, dns, raw/whois, cached, reverse_dns, registrar_reputation,
 * domain_age_risk, whois_privacy, screenshot_url, domain_suggestions,
 * verification_token, rate_limit, dnt) and the "score" key (security_score)
 * are NOT part of moduleRegistry() — the LEGACY (`?modules=` absent) path
 * still computes them inline in lookup.php exactly as before; only the NEW
 * `modules=core` / `modules=score` endpoints call into this file's
 * runCoreLookup() / the score-assembly branch of handleModuleRequest().
 *
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ═══════════════════════════════════════════════════════════════════
//  Module registry
// ═══════════════════════════════════════════════════════════════════

/**
 * The definitive module → check descriptor map.
 *
 * Each check-key maps to a descriptor:
 *   - 'fn'          string|null  Name of the existing lookup function to call.
 *                                 null for checks that are purely DERIVED from
 *                                 another check's result within the same module
 *                                 (spamhaus, hosting_risk) or that need custom
 *                                 gating too irregular to express generically
 *                                 (multi_dnsbl) — these are special-cased in
 *                                 runModuleChecks() rather than dispatched
 *                                 generically, but are still listed here so the
 *                                 registry's key-set stays the source of truth.
 *   - 'args'        'domain'|'first_a'|'first_a_or_ip'|'derived'|'special'
 *                                 How the check's subject is resolved:
 *                                   domain          → call fn($domain[, $apiKey])
 *                                   first_a         → call fn(firstARecord($dns)[, $apiKey]);
 *                                                     skip if no A record. No is_ip
 *                                                     fallback (matches reverse_ip's
 *                                                     original gate, which never
 *                                                     special-cased IP lookups).
 *                                   first_a_or_ip   → if is_ip, use $domain verbatim;
 *                                                     else use firstARecord($dns).
 *                                                     Skip if neither resolves.
 *                                   derived         → computed from another key's
 *                                                     already-resolved data within
 *                                                     the same module (see
 *                                                     'derives_from'); handled by a
 *                                                     dedicated branch, not generic
 *                                                     dispatch.
 *                                   special         → custom gating that doesn't fit
 *                                                     the patterns above (currently
 *                                                     only multi_dnsbl — see the
 *                                                     dedicated comment on that
 *                                                     branch in runModuleChecks()).
 *   - 'dnt'         bool         True if the legacy code skipped this check when
 *                                 the Do-Not-Track header was present.
 *   - 'key'         string|null  $config[...] key that must be non-empty for this
 *                                 check to run (null = no API key required).
 *   - 'domain_only' bool         True if the legacy code additionally required
 *                                 `!$isIpLookup && $domain` (skip reason 'is_ip'
 *                                 when the lookup subject is an IP address).
 *
 * @return array<string, array<string, array<string, mixed>>>
 */
function moduleRegistry(): array
{
    return [
        // ─── dns — no DNT gating on any of these ───
        'dns' => [
            'dnssec' => [
                'fn' => 'checkDnssec', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'ipv6' => [
                'fn' => 'checkIpv6Readiness', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'ns_diversity' => [
                'fn' => 'checkNsDiversity', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'dns_propagation' => [
                'fn' => 'checkDnsPropagation', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
        ],

        // ─── web — outbound probes to the user's host + its certificate ───
        'web' => [
            'ssl' => [
                'fn' => 'getSslInfo', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'http_headers' => [
                'fn' => 'auditHttpHeaders', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'tls_audit' => [
                'fn' => 'auditTlsVersions', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'http_versions' => [
                'fn' => 'checkHttpVersions', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'redirect_chain' => [
                'fn' => 'detectRedirectChain', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'response_times' => [
                'fn' => 'measureResponseTimes', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'tech_stack' => [
                'fn' => 'detectTechStack', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'robots_txt' => [
                'fn' => 'analyseRobotsTxt', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'cert_transparency' => [
                'fn' => 'checkCertTransparency', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'dane_tlsa' => [
                'fn' => 'checkDaneTlsa', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'caa_records' => [
                'fn' => 'checkCaaRecords', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
        ],

        // ─── email ───
        'email' => [
            'email_security' => [
                'fn' => 'checkEmailSecurity', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'mta_sts' => [
                'fn' => 'checkMtaSts', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'bimi' => [
                'fn' => 'checkBimi', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'smtp_security' => [
                'fn' => 'checkSmtpSecurity', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'hibp' => [
                'fn' => 'checkHibpDomain', 'args' => 'domain', 'dnt' => true,
                'key' => 'hibp_api_key', 'domain_only' => true,
            ],
            // Custom gating (see runModuleChecks): dns-derived first A record
            // takes priority; falls back to the bare IP only when $dns is
            // empty AND this is an IP lookup. Must run before 'spamhaus'.
            'multi_dnsbl' => [
                'fn' => 'checkMultiDnsbl', 'args' => 'special', 'dnt' => false,
                'key' => null, 'domain_only' => false,
            ],
            // Derived from multi_dnsbl's zen.spamhaus.org entry — see
            // deriveSpamhausFromMultiDnsbl(). Must run after 'multi_dnsbl'.
            'spamhaus' => [
                'fn' => null, 'args' => 'derived', 'dnt' => false,
                'key' => null, 'domain_only' => false, 'derives_from' => 'multi_dnsbl',
            ],
        ],

        // ─── reputation — fixed 3rd-party APIs ───
        'reputation' => [
            'safe_browsing' => [
                'fn' => 'checkSafeBrowsing', 'args' => 'domain', 'dnt' => true,
                'key' => 'safe_browsing_api_key', 'domain_only' => true,
            ],
            'virustotal' => [
                'fn' => 'checkVirusTotal', 'args' => 'domain', 'dnt' => true,
                'key' => 'virustotal_api_key', 'domain_only' => true,
            ],
            'phishtank' => [
                'fn' => 'checkPhishTank', 'args' => 'domain', 'dnt' => true,
                'key' => 'phishtank_api_key', 'domain_only' => true,
            ],
            'urlhaus' => [
                'fn' => 'checkUrlhaus', 'args' => 'domain', 'dnt' => true,
                'key' => null, 'domain_only' => true,
            ],
            'abuseipdb' => [
                'fn' => 'checkAbuseIPDB', 'args' => 'first_a_or_ip', 'dnt' => true,
                'key' => 'abuseipdb_api_key', 'domain_only' => false,
            ],
            'shodan' => [
                'fn' => 'checkShodan', 'args' => 'first_a_or_ip', 'dnt' => true,
                'key' => 'shodan_api_key', 'domain_only' => false,
            ],
            'geolocation' => [
                'fn' => 'getIpGeolocation', 'args' => 'first_a_or_ip', 'dnt' => true,
                'key' => null, 'domain_only' => false,
            ],
            // Derived from geolocation — UNCONDITIONAL in the legacy code (it
            // runs even when geolocation is null, e.g. under DNT). Must run
            // after 'geolocation'.
            'hosting_risk' => [
                'fn' => 'assessHostingRisk', 'args' => 'derived', 'dnt' => false,
                'key' => null, 'domain_only' => false, 'derives_from' => 'geolocation',
            ],
        ],

        // ─── subdomains ───
        'subdomains' => [
            'subdomains' => [
                'fn' => 'discoverSubdomains', 'args' => 'domain', 'dnt' => false,
                'key' => null, 'domain_only' => true,
            ],
            'reverse_ip' => [
                'fn' => 'reverseIpLookup', 'args' => 'first_a', 'dnt' => true,
                'key' => null, 'domain_only' => false,
            ],
        ],
    ];
}

// ═══════════════════════════════════════════════════════════════════
//  Module check runner
// ═══════════════════════════════════════════════════════════════════

/**
 * Run every check registered for a single module, applying its descriptor's
 * gating uniformly. Returns the resolved data plus a map of skipped checks
 * (key => reason) for observability — the 'skipped' map is new plumbing, not
 * part of the legacy response, so its reason strings are not covered by the
 * Step 1 byte-identity requirement (only 'data' feeds the response).
 *
 * @param string $module One of: dns, web, email, reputation, subdomains.
 * @param array{domain:string,is_ip:bool,dns:array,parsed:array,dnt:bool,config:array} $ctx
 * @return array{data: array<string, mixed>, skipped: array<string, string>}
 */
function runModuleChecks(string $module, array $ctx): array
{
    $registry = moduleRegistry();
    if (!isset($registry[$module])) {
        return ['data' => [], 'skipped' => []];
    }

    $domain = $ctx['domain'] ?? '';
    $isIp   = !empty($ctx['is_ip']);
    $dns    = $ctx['dns'] ?? [];
    $dnt    = !empty($ctx['dnt']);
    $config = $ctx['config'] ?? [];

    $data = [];
    $skipped = [];

    foreach ($registry[$module] as $checkKey => $desc) {
        // ── Derived: spamhaus, from the multi_dnsbl result resolved earlier
        //    in this same loop (registry order guarantees multi_dnsbl runs
        //    first — see moduleRegistry()'s 'email' block). ──
        if ($checkKey === 'spamhaus') {
            $multiDnsbl = $data['multi_dnsbl'] ?? null;
            if ($multiDnsbl !== null) {
                $data['spamhaus'] = deriveSpamhausFromMultiDnsbl($multiDnsbl);
            } else {
                $skipped['spamhaus'] = 'no_multi_dnsbl';
            }
            continue;
        }

        // ── Derived: hosting_risk, from the geolocation result resolved
        //    earlier in this same loop. UNCONDITIONAL — assessHostingRisk()
        //    is called even when geolocation is null (legacy behaviour: this
        //    line sat outside the `if (!$dnt)` guard around geolocation). ──
        if ($checkKey === 'hosting_risk') {
            $geolocation = $data['geolocation'] ?? null;
            $data['hosting_risk'] = assessHostingRisk($geolocation);
            continue;
        }

        // ── Special: multi_dnsbl. Legacy gating was NOT the generic
        //    first_a_or_ip pattern: it prioritises the dns-derived first A
        //    record (regardless of is_ip) and only falls back to the bare
        //    domain/IP when $dns is empty AND this is an IP lookup. ──
        if ($checkKey === 'multi_dnsbl') {
            $multiDnsbl = null;
            if (!empty($dns)) {
                $firstA = firstARecord($dns);
                if ($firstA !== null) {
                    $multiDnsbl = checkMultiDnsbl($firstA);
                }
            } elseif ($isIp) {
                $multiDnsbl = checkMultiDnsbl($domain);
            }
            if ($multiDnsbl !== null) {
                $data['multi_dnsbl'] = $multiDnsbl;
            } else {
                $skipped['multi_dnsbl'] = 'no_a_record';
            }
            continue;
        }

        // ── Generic descriptor-driven gating ──
        if ($desc['dnt'] && $dnt) {
            $skipped[$checkKey] = 'dnt';
            continue;
        }
        if (!empty($desc['domain_only']) && ($isIp || !$domain)) {
            $skipped[$checkKey] = 'is_ip';
            continue;
        }
        if (!empty($desc['key']) && empty($config[$desc['key']])) {
            $skipped[$checkKey] = 'no_api_key';
            continue;
        }

        $fn = $desc['fn'];

        if ($desc['args'] === 'domain') {
            $data[$checkKey] = !empty($desc['key'])
                ? $fn($domain, $config[$desc['key']])
                : $fn($domain);
            continue;
        }

        if ($desc['args'] === 'first_a' || $desc['args'] === 'first_a_or_ip') {
            $checkIp = ($desc['args'] === 'first_a_or_ip' && $isIp) ? $domain : null;
            if ($checkIp === null && !empty($dns)) {
                $checkIp = firstARecord($dns);
            }
            if (!$checkIp) {
                $skipped[$checkKey] = 'no_a_record';
                continue;
            }
            $data[$checkKey] = !empty($desc['key'])
                ? $fn($checkIp, $config[$desc['key']])
                : $fn($checkIp);
            continue;
        }
    }

    return ['data' => $data, 'skipped' => $skipped];
}

// ═══════════════════════════════════════════════════════════════════
//  Derived checks
// ═══════════════════════════════════════════════════════════════════

/**
 * Derive the legacy $spamhaus shape from a $multiDnsbl result, by pulling out
 * the zen.spamhaus.org entry. Mirrors checkSpamhaus()'s original
 * ['listed' => bool, 'lists' => [...]] shape so calculateSecurityScore() and
 * the frontend's data.spamhaus.listed / .lists[].label reads keep working
 * unchanged (Issue #100/#191).
 *
 * @param array $multiDnsbl The checkMultiDnsbl() result (must have a 'lists' key).
 * @return array{listed: bool, lists: array}
 */
function deriveSpamhausFromMultiDnsbl(array $multiDnsbl): array
{
    $zenEntry = null;
    foreach (($multiDnsbl['lists'] ?? []) as $entry) {
        if (($entry['zone'] ?? '') === 'zen.spamhaus.org') {
            $zenEntry = $entry;
            break;
        }
    }
    return [
        'listed' => $zenEntry !== null,
        'lists'  => $zenEntry !== null ? [$zenEntry] : [],
    ];
}

// ═══════════════════════════════════════════════════════════════════
//  Per-module response cache (Issue #196, Step 3)
//
//  Independent cache entries per module (plus 'core'), so a future
//  `?modules=` fetch can read just the module a UI tab needs instead of
//  paying for the whole ~35-check pipeline. Step 3 only WARMS these caches
//  (from the existing legacy full-pipeline path, via runModuleChecks()'s
//  result) — nothing reads them yet; that lands with the Step 4 dispatcher.
//
//  Keys: 'mod:{module}:{domain}' for the dns module (its content doesn't
//  vary by Do-Not-Track — no requests it makes are DNT-gated, see
//  moduleRegistry()'s 'dns' block, so DNT and non-DNT callers safely share
//  one cache entry) and 'mod:{module}:{domain}:dnt' / 'mod:core:{domain}:dnt'
//  for every other module — several of their checks skip outbound calls
//  under DNT (see each descriptor's 'dnt' flag), so a DNT response must
//  never be served to (or overwrite the cache for) a non-DNT caller.
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the getCached()/setCache() key for a module's cached response.
 * getCached()/setCache() key on md5(...) of whatever string they're given
 * (see their use for the domain-keyed WHOIS cache and the 'full:' response
 * cache), so a composite "namespace:module:domain[:dnt]" string is exactly
 * the pattern already established by the 'full:' cache in lookup.php.
 */
function moduleCacheKey(string $module, string $domain, bool $dnt): string
{
    $suffix = ($dnt && $module !== 'dns') ? ':dnt' : '';
    return 'mod:' . $module . ':' . $domain . $suffix;
}

/**
 * Read a module's cached response, or null on a miss / corrupt entry.
 *
 * @param string $module 'core', or one of moduleRegistry()'s keys.
 * @return array{data: array<string, mixed>, skipped: array<string, string>}|null
 */
function getModuleCache(string $module, string $domain, bool $dnt): ?array
{
    $raw = getCached(moduleCacheKey($module, $domain, $dnt), CACHE_TTL);
    if ($raw === null) {
        return null;
    }
    $decoded = json_decode($raw, true);
    return is_array($decoded) ? $decoded : null;
}

/**
 * Store a module's response payload (the ['data' => ..., 'skipped' => ...]
 * shape runModuleChecks() returns; runCoreLookup()'s Step-4 caller uses the
 * same shape for 'core').
 */
function setModuleCache(string $module, string $domain, bool $dnt, array $payload): void
{
    setCache(moduleCacheKey($module, $domain, $dnt), json_encode($payload), CACHE_TTL);
}

// ═══════════════════════════════════════════════════════════════════
//  lookup_token — a short-lived HMAC that exempts module fetches from
//  rate-limit counting (Issue #196, Step 4)
//
//  A `modules=core` response issues one of these; the frontend replays it on
//  its follow-up `modules={dns,web,email,reputation,subdomains,score}`
//  fetches for the SAME domain (within 180s) so a single page view doesn't
//  burn ~6 rate-limit slots. It is bound to the calling session (or, for
//  API-key callers, to the key) so a token minted for one caller can't be
//  replayed by another. ANY validation failure (expired, wrong domain,
//  wrong binding, tampered/malformed) must fall back to normal COUNTED
//  rate limiting — never a 403 — so validateLookupToken() never throws and
//  always resolves to a plain bool.
// ═══════════════════════════════════════════════════════════════════

/**
 * URL-safe base64 (RFC 4648 §5) without padding.
 */
function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

/**
 * Inverse of base64UrlEncode(). Returns false on malformed input (never
 * throws) so callers can treat a bad token as a validation failure.
 */
function base64UrlDecode(string $data)
{
    $remainder = strlen($data) % 4;
    if ($remainder > 0) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(strtr($data, '-_', '+/'), true);
}

/**
 * The HMAC secret used to sign/verify lookup_token values. 32 random bytes,
 * created lazily on first use. Stored under CACHE_DIR (the same ephemeral/
 * writable location the file-cache backend and rate-limit files already
 * use) — NEVER under web/.auth/ (that directory is for third-party
 * provider API keys the user supplies, deployed as a sibling of the web
 * root; this is a purely internal, self-generated signing key with no
 * meaning outside this app). chmod 0600 so it's unreadable to other local
 * users, mirroring how the app treats every other locally-stored secret.
 * Re-reads the file on every call rather than caching in a static — a
 * single request issues/validates at most a couple of tokens, so the extra
 * file_get_contents() calls are negligible, and staying stateless avoids
 * a process ever pinning a stale in-memory secret past a key rotation.
 */
function moduleTokenSecret(): string
{
    if (!is_dir(CACHE_DIR)) {
        @mkdir(CACHE_DIR, 0755, true);
    }

    $path = CACHE_DIR . DIRECTORY_SEPARATOR . '.module_token_key';

    $existing = @file_get_contents($path);
    if ($existing !== false && strlen($existing) === 32) {
        $secret = $existing;
        return $secret;
    }

    // Lazily create it under an exclusive lock so concurrent first-requests
    // don't race to generate different keys (which would silently
    // invalidate tokens a sibling request just issued) — mirrors the
    // flock() pattern updateTldDataIfNeeded() already uses in functions.php.
    $lockHandle = @fopen($path . '.lock', 'c');
    if ($lockHandle && @flock($lockHandle, LOCK_EX)) {
        // Re-check under the lock — another process may have just created it.
        $existing = @file_get_contents($path);
        if ($existing !== false && strlen($existing) === 32) {
            $secret = $existing;
        } else {
            $secret = random_bytes(32);
            file_put_contents($path, $secret, LOCK_EX);
            @chmod($path, 0600);
        }
        @flock($lockHandle, LOCK_UN);
        @fclose($lockHandle);
        return $secret;
    }
    if ($lockHandle) {
        @fclose($lockHandle);
    }

    // Lock unavailable (e.g. read-only lock dir) — best-effort read-or-create,
    // extremely unlikely to actually race outside of the very first request.
    $existing = @file_get_contents($path);
    if ($existing !== false && strlen($existing) === 32) {
        $secret = $existing;
        return $secret;
    }
    $secret = random_bytes(32);
    @file_put_contents($path, $secret, LOCK_EX);
    @chmod($path, 0600);
    return $secret;
}

/**
 * Resolve the caller-binding used by lookup_token issuance/validation:
 * hash('sha256', $apiKeyHash) for an authenticated API-key caller (where
 * $apiKeyHash is hash('sha256', $rawKey) — the same hash validateApiKey()
 * looks up by), otherwise hash('sha256', session_id()) for a CSRF/session
 * caller. Shared by lookup.php's legacy-path token issuance and
 * handleModuleRequest() so a token minted by one path validates on the
 * other for the same caller.
 */
function resolveLookupTokenBinding(?array $apiKeyConfig, string $apiKeyHeader): string
{
    if ($apiKeyConfig !== null && $apiKeyHeader !== '') {
        $apiKeyHash = hash('sha256', $apiKeyHeader);
        return hash('sha256', $apiKeyHash);
    }
    return hash('sha256', (string)session_id());
}

/**
 * Issue a lookup_token for $domain, bound to $binding, valid for 180s.
 * Format: base64url(json{v,d,b,exp,n}) . '.' . base64url(hmac-sha256).
 */
function issueLookupToken(string $domain, string $binding): string
{
    $payload = [
        'v'   => 1,
        'd'   => $domain,
        'b'   => $binding,
        'exp' => time() + 180,
        'n'   => bin2hex(random_bytes(8)),
    ];
    $payloadB64 = base64UrlEncode(json_encode($payload));
    $signature = hash_hmac('sha256', $payloadB64, moduleTokenSecret(), true);

    return $payloadB64 . '.' . base64UrlEncode($signature);
}

/**
 * Validate a lookup_token for $domain + $binding. Returns false on ANY
 * failure (malformed shape, bad base64/JSON, tampered/invalid HMAC,
 * expired, wrong domain, wrong binding) — never throws. Callers must treat
 * false as "fall back to normal rate limiting", never as an auth error.
 */
function validateLookupToken(string $token, string $domain, string $binding): bool
{
    if ($token === '' || substr_count($token, '.') !== 1) {
        return false;
    }

    [$payloadB64, $sigB64] = explode('.', $token, 2);
    if ($payloadB64 === '' || $sigB64 === '') {
        return false;
    }

    $providedSignature = base64UrlDecode($sigB64);
    if ($providedSignature === false || $providedSignature === '') {
        return false;
    }

    $expectedSignature = hash_hmac('sha256', $payloadB64, moduleTokenSecret(), true);
    if (!hash_equals($expectedSignature, $providedSignature)) {
        return false;
    }

    $payloadJson = base64UrlDecode($payloadB64);
    if ($payloadJson === false || $payloadJson === '') {
        return false;
    }

    $payload = json_decode($payloadJson, true);
    if (!is_array($payload)) {
        return false;
    }
    if (!isset($payload['v'], $payload['d'], $payload['b'], $payload['exp'])) {
        return false;
    }
    if ((int)$payload['v'] !== 1) {
        return false;
    }
    if (!is_string($payload['d']) || !is_string($payload['b'])) {
        return false;
    }
    if (!is_int($payload['exp']) && !is_numeric($payload['exp'])) {
        return false;
    }
    if ((int)$payload['exp'] <= time()) {
        return false;
    }
    if ($payload['d'] !== $domain) {
        return false;
    }
    if ($payload['b'] !== $binding) {
        return false;
    }

    return true;
}

// ═══════════════════════════════════════════════════════════════════
//  Core lookup (Issue #196, Step 4)
//
//  The CORE half of the legacy pipeline (lookup.php's IP branch + domain
//  branch: raw-whois cache read, RDAP-first with WHOIS fallback via
//  runCommandWithTimeout(), availability detection, WHOIS field parsing,
//  DNS records, reverse DNS) extracted verbatim so it can run standalone
//  for a `modules=core` request. This is a byte-for-byte port of the logic
//  the LEGACY (`?modules=` absent) path still runs inline in lookup.php —
//  that inline copy is left untouched (see lookup.php's comment at the top
//  of the domain/IP branch) so the legacy response stays byte-identical;
//  this function is a NEW, separate call path used only by
//  handleModuleRequest()'s `core` branch.
//
//  Deliberately excluded (stays legacy-path-only): the 'full:' response
//  cache — a `modules=core` request always re-derives availability/parsed/
//  dns fresh (subject only to the raw-whois cache below), so a stale
//  full-pipeline cache entry from a differently-shaped legacy request can
//  never leak into the module endpoints.
//
//  @return array On success: domain, is_ip, availability, data_source,
//                 parsed, dns, raw, cached, reverse_dns. On invalid input:
//                 ['error' => string] — no exception is thrown.
// ═══════════════════════════════════════════════════════════════════

function runCoreLookup(string $rawInput, string $sourceParam, bool $dnt): array
{
    $isIpLookup = isIpAddress($rawInput);
    $reverseDns = null;

    if ($isIpLookup) {
        $domain = $rawInput;
        $reverseDns = reverseDnsLookup($domain);
        $whoisText = ipWhoisLookup($domain);
        $dataSource = 'whois';
        $fromCache = false;
        $availability = 'n/a';
        $parsed = [];
        $dns = [];

        if ($reverseDns) {
            $parsed['PTR Hostname'] = $reverseDns;
            $dns = getDnsRecords($reverseDns);
        }
    } else {
        $domain = sanitizeDomainInput($rawInput);

        if (!$domain || !isValidDomain($domain)) {
            return ['error' => 'Invalid domain name.'];
        }

        // ─── Lookup pipeline (mirrors the legacy domain branch exactly) ───
        $whoisText = getCached($domain);
        $fromCache = ($whoisText !== null);
        $dataSource = 'whois';

        if ($fromCache) {
            if (!$dnt) trackLookup('cache_hit', $domain);
        }

        // Try RDAP first (unless source=whois or cached) — source=whois
        // "bypasses" RDAP entirely, falling straight through to the system
        // WHOIS command below.
        if (!$fromCache && $sourceParam === 'rdap') {
            $rdap = rdapLookup($domain);
            if ($rdap) {
                $dataSource = 'rdap';
                $whoisText = formatRdapResponse($rdap);
                if (!$dnt) trackLookup('rdap', $domain);
            }
        }

        // Fall back to system WHOIS
        if (!$whoisText) {
            $whoisText = runCommandWithTimeout("whois " . escapeshellarg($domain), 8);
            $dataSource = 'whois';
            if (!$dnt) trackLookup('whois', $domain);
        }

        // Cache result
        if ($whoisText && !$fromCache) {
            setCache($domain, $whoisText);
        }

        // Build response
        $availability = 'unknown';
        if ($whoisText) {
            $availability = detectAvailability($whoisText);
        }

        $parsed = [];
        if ($whoisText) {
            $parsed = parseWhoisFields($whoisText);
        }

        $dns = getDnsRecords($domain);
    }

    return [
        'domain'       => $domain,
        'is_ip'        => $isIpLookup,
        'availability' => $availability,
        'data_source'  => $dataSource,
        'parsed'       => $parsed,
        'dns'          => $dns,
        'raw'          => $whoisText,
        'cached'       => $fromCache,
        'reverse_dns'  => $reverseDns,
    ];
}

// ═══════════════════════════════════════════════════════════════════
//  Module HTTP endpoint dispatcher (Issue #196, Step 4)
//
//  Handles a `?modules=core|score|dns|web|email|reputation|subdomains`
//  request. Exits (via sendJson()/direct echo+exit for the pre-session
//  400/429 paths) — never returns. Wired into lookup.php AFTER the
//  API-key/CSRF auth gate (so every module request is already
//  authenticated by the time this runs) and BEFORE the legacy
//  unconditional rate-limit call.
// ═══════════════════════════════════════════════════════════════════

function handleModuleRequest(string $moduleParam, ?array $apiKeyConfig, bool $dnt, array $config): void
{
    // 1. Validate the module parameter.
    $validModules = array_merge(['core', 'score'], array_keys(moduleRegistry()));
    if (!in_array($moduleParam, $validModules, true)) {
        http_response_code(400);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['error' => 'Unknown module: ' . $moduleParam]);
        exit;
    }

    // 2. Sanitize + validate the domain (IP allowed for every module type —
    //    per-check gating inside runCoreLookup()/runModuleChecks() already
    //    knows how to treat is_ip correctly for each check; 'dns'/'web'/
    //    'subdomains' just fully skip for an IP, exactly as they do today).
    $rawInput = isset($_POST['domain']) ? trim((string)$_POST['domain']) : '';
    $isIpLookup = isIpAddress($rawInput);
    if ($isIpLookup) {
        $domain = $rawInput;
    } else {
        $domain = sanitizeDomainInput($rawInput);
        if (!$domain || !isValidDomain($domain)) {
            http_response_code(400);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'Invalid domain name.']);
            exit;
        }
    }

    // 3. Rate-limit exemption via lookup_token.
    $apiKeyHeader = isset($_SERVER['HTTP_X_API_KEY']) ? trim($_SERVER['HTTP_X_API_KEY']) : '';
    $binding = resolveLookupTokenBinding($apiKeyConfig, $apiKeyHeader);
    $tokenParam = isset($_POST['lookup_token']) ? (string)$_POST['lookup_token'] : '';
    $exempt = ($tokenParam !== '') && validateLookupToken($tokenParam, $domain, $binding);

    // 4. Rate limit — exempt callers are never counted. Non-exempt callers
    //    use the same session + IP dual limiter as the legacy path, so a
    //    burst of module fetches without a valid token is capped exactly
    //    like a burst of full lookups would be.
    $limit = $apiKeyConfig ? getApiKeyRateLimit($apiKeyConfig) : RATE_LIMIT_MAX;
    if (!$exempt) {
        if (!checkRateLimit($limit) || !checkIpRateLimit($limit)) {
            header('Retry-After: ' . rateLimitRetryAfterSeconds());
            http_response_code(429);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => 'Rate limit exceeded. Please wait before trying again.']);
            exit;
        }
    }
    $rateLimitUsed = isset($_SESSION['rate_limit']['count']) ? $_SESSION['rate_limit']['count'] : 0;
    $rateLimitRemaining = max(0, $limit - $rateLimitUsed);

    // 5. CRITICAL — release the session lock before any network/shell work,
    //    so concurrent module fetches for the same visitor don't serialize
    //    on PHP's session file lock (the entire point of this endpoint).
    session_write_close();

    $sourceParam = 'rdap';
    if (isset($_GET['source'])) {
        $sourceParam = strtolower(trim($_GET['source']));
    }
    if (isset($_POST['source'])) {
        $sourceParam = strtolower(trim($_POST['source']));
    }
    if ($sourceParam !== 'rdap' && $sourceParam !== 'whois') {
        $sourceParam = 'rdap';
    }

    $jsonFormat = ($apiKeyConfig !== null);
    if (isset($_GET['format']) && strtolower(trim($_GET['format'])) === 'json') {
        $jsonFormat = true;
    }

    // 6. core
    if ($moduleParam === 'core') {
        $core = runCoreLookup($rawInput, $sourceParam, $dnt);
        if (isset($core['error'])) {
            http_response_code(400);
            header('Content-Type: application/json; charset=utf-8');
            echo json_encode(['error' => $core['error']]);
            exit;
        }

        // Off-request-path TLD/PSL refresh + lookup stats — CORE/legacy
        // only, never for enrichment/score module fetches (those would
        // otherwise re-trigger this on every tab click).
        register_shutdown_function(function () {
            updateTldDataIfNeeded();
        });

        $lookupToken = issueLookupToken($core['domain'], $binding);

        // Which enrichment module tabs the frontend should fetch next.
        if ($core['availability'] === 'available') {
            $modulesAvailable = []; // unregistered — legacy skips the whole enrichment pipeline too
        } elseif ($core['is_ip']) {
            $modulesAvailable = ['email', 'reputation']; // the only modules with any IP-applicable checks
        } else {
            $modulesAvailable = array_keys(moduleRegistry());
        }

        // Warm mod:core so the enrichment-gate below (and modules=score)
        // can read availability/dns/parsed without repeating the WHOIS/
        // RDAP fetch or a redundant getDnsRecords() call.
        setModuleCache('core', $core['domain'], $dnt, [
            'data' => [
                'availability' => $core['availability'],
                'data_source'  => $core['data_source'],
                'parsed'       => $core['parsed'],
                'dns'          => $core['dns'],
                'is_ip'        => $core['is_ip'],
            ],
            'skipped' => [],
        ]);

        $rateLimitField = ['used' => $rateLimitUsed, 'remaining' => $rateLimitRemaining, 'limit' => $limit];

        if ($jsonFormat) {
            $payload = [
                'domain'            => $core['domain'],
                'is_ip'             => $core['is_ip'],
                'availability'      => $core['availability'],
                'data_source'       => $core['data_source'],
                'parsed'            => $core['parsed'],
                'dns'               => $core['dns'],
                'raw'               => $core['raw'],
                'cached'            => $core['cached'],
                'lookup_token'      => $lookupToken,
                'modules_available' => $modulesAvailable,
                'rate_limit'        => $rateLimitField,
                'dnt'               => $dnt,
            ];
            if ($core['reverse_dns']) {
                $payload['reverse_dns'] = $core['reverse_dns'];
            }
        } else {
            $whoisOutput = '';
            if ($core['raw']) {
                $whoisOutput = $core['raw'];
                if (!empty($config['mask_whois_contacts'])) {
                    $whoisOutput = preg_replace('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', '[email redacted]', $whoisOutput);
                    $whoisOutput = preg_replace('/\+?[0-9][\d\s.()-]{7,}/', '[phone redacted]', $whoisOutput);
                }
            }
            $payload = [
                'whois'             => htmlspecialchars($whoisOutput, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
                'domain'            => $core['domain'],
                'is_ip'             => $core['is_ip'],
                'availability'      => $core['availability'],
                'data_source'       => $core['data_source'],
                'parsed'            => $core['parsed'],
                'dns'               => $core['dns'],
                'cached'            => $core['cached'],
                'lookup_token'      => $lookupToken,
                'modules_available' => $modulesAvailable,
                'rate_limit'        => $rateLimitField,
                'dnt'               => $dnt,
            ];
            if ($core['reverse_dns']) {
                $payload['reverse_dns'] = $core['reverse_dns'];
            }
        }

        sendJson($payload);
    }

    // 8. score (checked ahead of the generic enrichment branch below so it
    //    doesn't fall through to the moduleRegistry()-driven dispatch).
    if ($moduleParam === 'score') {
        $inputsMissing = [];
        $scoreInputs = [
            'ssl' => null, 'http_headers' => null, 'dnssec' => null,
            'email_security' => null, 'mta_sts' => null, 'tls_audit' => null,
            'spamhaus' => null, 'caa_records' => null, 'urlhaus' => null,
        ];

        $webCache = getModuleCache('web', $domain, $dnt);
        if ($webCache !== null) {
            $scoreInputs['ssl'] = $webCache['data']['ssl'] ?? null;
            $scoreInputs['http_headers'] = $webCache['data']['http_headers'] ?? null;
            $scoreInputs['tls_audit'] = $webCache['data']['tls_audit'] ?? null;
            $scoreInputs['caa_records'] = $webCache['data']['caa_records'] ?? null;
        } else {
            $inputsMissing[] = 'web';
        }

        $dnsCache = getModuleCache('dns', $domain, $dnt);
        if ($dnsCache !== null) {
            $scoreInputs['dnssec'] = $dnsCache['data']['dnssec'] ?? null;
        } else {
            $inputsMissing[] = 'dns';
        }

        $emailCache = getModuleCache('email', $domain, $dnt);
        if ($emailCache !== null) {
            $scoreInputs['email_security'] = $emailCache['data']['email_security'] ?? null;
            $scoreInputs['mta_sts'] = $emailCache['data']['mta_sts'] ?? null;
            $spamhaus = $emailCache['data']['spamhaus'] ?? null;
            if ($spamhaus === null && isset($emailCache['data']['multi_dnsbl'])) {
                // Defensive fallback: derive it if a cache entry somehow has
                // multi_dnsbl but not the already-derived spamhaus shape.
                $spamhaus = deriveSpamhausFromMultiDnsbl($emailCache['data']['multi_dnsbl']);
            }
            $scoreInputs['spamhaus'] = $spamhaus;
        } else {
            $inputsMissing[] = 'email';
        }

        $reputationCache = getModuleCache('reputation', $domain, $dnt);
        if ($reputationCache !== null) {
            $scoreInputs['urlhaus'] = $reputationCache['data']['urlhaus'] ?? null;
        } else {
            $inputsMissing[] = 'reputation';
        }

        // Mirrors the legacy gate (`if (!$isIpLookup && $domain)`) — the
        // score has no meaning for a bare IP lookup.
        $securityScore = $isIpLookup ? null : calculateSecurityScore($scoreInputs);

        sendJson([
            'domain'       => $domain,
            'module'       => 'score',
            'status'       => 'ok',
            'dnt'          => $dnt,
            'cached'       => false,
            'generated_at' => time(),
            'data'         => ['security_score' => $securityScore, 'inputs_missing' => $inputsMissing],
            'skipped'      => [],
        ]);
    }

    // 7. Enrichment group (dns, web, email, reputation, subdomains) — the
    //    only moduleParam values that can still reach this point, since 1
    //    validated moduleParam against the registry and core/score already
    //    exited above.
    $coreCache = getModuleCache('core', $domain, $dnt);
    $availability = null;
    if ($coreCache !== null && isset($coreCache['data']['availability'])) {
        $availability = $coreCache['data']['availability'];
    } elseif (!$isIpLookup) {
        // No core cache yet (this module fetch raced ahead of, or was
        // issued without, a prior modules=core call) — fall back to the
        // raw-whois cache the core path also reads, so the availability
        // gate still works instead of unconditionally "proceeding".
        $rawWhois = getCached($domain);
        if ($rawWhois !== null) {
            $availability = detectAvailability($rawWhois);
        }
    }

    if ($availability === 'available') {
        sendJson([
            'domain'       => $domain,
            'module'       => $moduleParam,
            'status'       => 'skipped_available',
            'dnt'          => $dnt,
            'cached'       => false,
            'generated_at' => time(),
            'data'         => [],
            'skipped'      => [],
        ]);
    }

    $moduleCacheHit = getModuleCache($moduleParam, $domain, $dnt);
    if ($moduleCacheHit !== null) {
        sendJson([
            'domain'       => $domain,
            'module'       => $moduleParam,
            'status'       => 'ok',
            'dnt'          => $dnt,
            'cached'       => true,
            'generated_at' => time(),
            'data'         => $moduleCacheHit['data'] ?? [],
            'skipped'      => $moduleCacheHit['skipped'] ?? [],
        ]);
    }

    // Reuse mod:core's already-resolved dns/parsed when available (skips a
    // redundant getDnsRecords() shell-out); otherwise resolve fresh.
    $dns = $coreCache['data']['dns'] ?? null;
    if ($dns === null) {
        $dns = getDnsRecords($domain);
    }
    $parsed = $coreCache['data']['parsed'] ?? [];

    $ctx = [
        'domain' => $domain,
        'is_ip'  => $isIpLookup,
        'dns'    => $dns,
        'parsed' => $parsed,
        'dnt'    => $dnt,
        'config' => $config,
    ];

    $result = runModuleChecks($moduleParam, $ctx);
    setModuleCache($moduleParam, $domain, $dnt, $result);

    sendJson([
        'domain'       => $domain,
        'module'       => $moduleParam,
        'status'       => 'ok',
        'dnt'          => $dnt,
        'cached'       => false,
        'generated_at' => time(),
        'data'         => $result['data'],
        'skipped'      => $result['skipped'],
    ]);
}
