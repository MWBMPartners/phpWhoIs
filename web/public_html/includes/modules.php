<?php
/**
 * mwWhoIs — Module registry (Issue #196, Step 1)
 *
 * Pure extraction of the enrichment pipeline that used to live inline in
 * lookup.php's `if ($availability !== 'available') { ... }` block. This file
 * introduces NO behaviour change: moduleRegistry() is a descriptor map of the
 * exact same checks, with the exact same gating (DNT / API key / IP-lookup /
 * first-A-record) the inline code used to apply, and runModuleChecks() walks
 * that map to reproduce the same function calls in the same conditions.
 *
 * Deliberately NOT included here (Step 1 defers these — see Issue #196 plan
 * §7 STEPS, step 1): runCoreLookup(), the module HTTP endpoint dispatcher,
 * lookup_token issuance, per-module caching, and curlMultiBatch(). Those are
 * Steps 2-4+ of the re-architecture. The "core" response keys (domain, is_ip,
 * availability, data_source, parsed, dns, raw/whois, cached, reverse_dns,
 * registrar_reputation, domain_age_risk, whois_privacy, screenshot_url,
 * domain_suggestions, verification_token, rate_limit, dnt) and the "score"
 * key (security_score) are NOT part of this registry — they remain inline in
 * lookup.php exactly as before.
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
