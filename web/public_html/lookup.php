<?php
/**
 * mwWhoIs Lookup API
 * Handles WHOIS/RDAP lookups, DNS queries, and domain availability detection.
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ─── Shared session config (must match index.php) ───
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'session_config.php';

// ─── Security headers ───
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: Thu, 01 Jan 1970 00:00:00 GMT");
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'none'; frame-ancestors 'none'");
// HSTS (Issue #203) — only sent over HTTPS; a proxy/load-balancer terminating
// TLS in front of the app sets X-Forwarded-Proto rather than $_SERVER['HTTPS'].
$_isHttpsRequest = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
if ($_isHttpsRequest) {
    header("Strict-Transport-Security: max-age=31536000; includeSubDomains");
}

// ─── Constants ───
define('IANA_TLD_URL', 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt');
define('IANA_TLD_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'tlds.txt');
define('PSL_ICANN_URL', 'https://publicsuffix.org/list/public_suffix_list.dat');
define('SL_SUFFIXES_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'second_level_suffixes.txt');
define('TLD_META_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'tld_metadata.json');
define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');
define('CACHE_TTL', 900);
define('RATE_LIMIT_MAX', 30);
define('RATE_LIMIT_WINDOW', 60);
define('MAX_DOMAIN_LENGTH', 253);
define('MAX_POST_SIZE', 1024);

// ─── Do Not Track (Issue #85) ───
$dnt = (isset($_SERVER['HTTP_DNT']) && $_SERVER['HTTP_DNT'] === '1');
header($dnt ? 'Tk: N' : 'Tk: ?');

// ─── Load config & functions ───
$config = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php';
}
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'functions.php';
// Module registry + endpoints (Issue #196, Steps 1/3/4) — moduleRegistry()/
// runModuleChecks()/deriveSpamhausFromMultiDnsbl() used by the enrichment
// loop below, plus the `?modules=` dispatcher (handleModuleRequest()) wired
// in further down.
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'modules.php';


// ═══════════════════════════════════════════════════════════════════
//  Module-request collision guard (Issue #196 Step 4) — `?modules=` is a
//  distinct endpoint from the two below (each has its own auth/rate-limit
//  handling) and must run BEFORE either of them, so a request combining
//  `modules` with `suggest`/`dns_propagation_only` is rejected outright
//  rather than silently falling through to whichever branch happens to be
//  checked first.
// ═══════════════════════════════════════════════════════════════════

if (isset($_GET['modules']) && trim((string)$_GET['modules']) !== '' &&
    ((isset($_GET['suggest']) && $_GET['suggest'] === '1') || !empty($_POST['dns_propagation_only']))) {
    header('Content-Type: application/json; charset=utf-8');
    http_response_code(400);
    echo json_encode(['error' => 'The modules parameter cannot be combined with suggest or dns_propagation_only.']);
    exit;
}


// ═══════════════════════════════════════════════════════════════════
//  On-demand domain suggestions endpoint (Issue #164)
// ═══════════════════════════════════════════════════════════════════

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['suggest']) && $_GET['suggest'] === '1') {
    header('Content-Type: application/json');

    // Auth gate (Issue #198): this endpoint used to run with NO auth check at
    // all, letting anonymous cross-origin callers fire the parallel RDAP grid.
    // Require the same policy as the main handler below — a valid API key OR
    // a valid CSRF token.
    $suggestApiKeyHeader = isset($_SERVER['HTTP_X_API_KEY']) ? trim($_SERVER['HTTP_X_API_KEY']) : '';
    $suggestApiKeyConfig = $suggestApiKeyHeader ? validateApiKey($suggestApiKeyHeader) : null;
    if (!$suggestApiKeyConfig && !validateCsrfToken()) {
        http_response_code(403);
        echo json_encode(['error' => 'Invalid request. Please refresh the page and try again.']);
        exit;
    }

    $suggestDomain = isset($_POST['domain']) ? trim((string)$_POST['domain']) : '';
    $suggestDomain = sanitizeDomainInput($suggestDomain);
    if (!$suggestDomain || !isValidDomain($suggestDomain)) {
        echo json_encode(['suggestions' => [], 'grid' => null]);
        exit;
    }
    // Rate-limit the suggest endpoint just like the main lookup.
    if (!checkRateLimit() || !checkIpRateLimit()) {
        header('Retry-After: ' . rateLimitRetryAfterSeconds());
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded.']);
        exit;
    }
    // session no longer needed — release the lock so concurrent requests aren't serialized
    session_write_close();
    $grid = getTldAvailabilityGrid($suggestDomain);
    $suggestions = [];
    foreach ($grid['results'] as $r) {
        if ($r['availability'] === 'available') {
            $suggestions[] = $r['domain'];
        }
    }
    echo json_encode([
        'suggestions' => $suggestions,
        'grid' => $grid,
    ]);
    exit;
}


// ═══════════════════════════════════════════════════════════════════
//  Main request handler
// ═══════════════════════════════════════════════════════════════════

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit;
}

// Validate input size
if (!validateInputSize()) {
    sendError('Request too large.', 413);
}

// Parameters (sanitize GET inputs)
$formatParam = '';
if (isset($_GET['format'])) {
    $formatParam = strtolower(trim($_GET['format']));
}
$jsonFormat = ($formatParam === 'json');

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

// API key authentication (Issue #61)
$apiKeyConfig = null;
$apiKeyHeader = isset($_SERVER['HTTP_X_API_KEY']) ? trim($_SERVER['HTTP_X_API_KEY']) : '';
if ($apiKeyHeader) {
    $apiKeyConfig = validateApiKey($apiKeyHeader);
    if (!$apiKeyConfig) {
        sendError('Invalid API key.', 401);
    }
    $jsonFormat = true; // API key users always get JSON
}

// CSRF required unless a valid API key was supplied (Issue #198). Previously
// `format=json` alone bypassed CSRF, which let an anonymous, cross-origin
// `POST lookup?format=json` (no API key) run the entire outbound lookup
// pipeline with no auth at all — usable for CSRF-to-SSRF and resource abuse.
if (!$apiKeyConfig && !validateCsrfToken()) {
    sendError('Invalid request. Please refresh the page and try again.', 403);
}

// ═══════════════════════════════════════════════════════════════════
//  Module endpoint dispatch (Issue #196, Step 4) — `?modules=core|score|
//  dns|web|email|reputation|subdomains`. Runs AFTER the auth gate above
//  (every module request is already authenticated) and BEFORE the
//  unconditional rate-limit call below (handleModuleRequest() applies its
//  own rate limiting, with a lookup_token exemption). Exits; never returns.
// ═══════════════════════════════════════════════════════════════════
$moduleParam = isset($_GET['modules']) ? strtolower(trim((string)$_GET['modules'])) : '';
if ($moduleParam !== '') {
    handleModuleRequest($moduleParam, $apiKeyConfig, $dnt, $config);
}

// Rate limit — use API key tier limit if applicable
$rateLimit = $apiKeyConfig ? getApiKeyRateLimit($apiKeyConfig) : RATE_LIMIT_MAX;
if (!checkRateLimit($rateLimit) || !checkIpRateLimit($rateLimit)) {
    header('Retry-After: ' . rateLimitRetryAfterSeconds());
    sendError('Rate limit exceeded. Please wait before trying again.', 429);
}

// Rate limit quota info (Issue #118) + HTTP headers (Issue #142)
$rateLimitUsed = isset($_SESSION['rate_limit']['count']) ? $_SESSION['rate_limit']['count'] : 0;
$rateLimitRemaining = max(0, $rateLimit - $rateLimitUsed);
$rateLimitReset = isset($_SESSION['rate_limit']['start']) ? ($_SESSION['rate_limit']['start'] + RATE_LIMIT_WINDOW) : (time() + RATE_LIMIT_WINDOW);
header('X-RateLimit-Limit: ' . $rateLimit);
header('X-RateLimit-Remaining: ' . $rateLimitRemaining);
header('X-RateLimit-Reset: ' . $rateLimitReset);

// session no longer needed — release the lock so concurrent requests aren't serialized
session_write_close();

// Update TLD data (IANA + second-level suffixes, throttled to once per day).
// Issue #193: deferred to a shutdown function so it runs AFTER the response has
// been flushed to the client (see sendJson()'s fastcgi_finish_request() call)
// instead of one unlucky request paying the ~10s fetch cost inline.
register_shutdown_function(function () {
    updateTldDataIfNeeded();
});

// Parse & validate input
$rawDomainInput = '';
if (isset($_POST['domain'])) {
    $rawDomainInput = trim((string)$_POST['domain']);
}

// DNS propagation-only refresh (lightweight, skips full lookup)
if (!empty($_POST['dns_propagation_only'])) {
    $domain = sanitizeDomainInput($rawDomainInput);
    if (!$domain || !isValidDomain($domain)) {
        sendError('Invalid domain name.');
    }
    header('Content-Type: application/json; charset=utf-8');
    // session no longer needed — release the lock so concurrent requests aren't serialized
    session_write_close();
    // Issue #194: curated subset by default; pass full=1 to get every enabled resolver.
    $fullPropagation = !empty($_POST['full']);
    echo json_encode(['dns_propagation' => checkDnsPropagation($domain, $fullPropagation)]);
    // This endpoint doesn't go through sendJson() — flush explicitly so the deferred
    // TLD refresh above doesn't keep this (lightweight, frequently-polled) endpoint waiting.
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
    exit;
}

// ─── Check if input is an IP address (Issue #45) ───
$isIpLookup = isIpAddress($rawDomainInput);
$reverseDns = null;

if ($isIpLookup) {
    $domain = $rawDomainInput;
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
    $domain = sanitizeDomainInput($rawDomainInput);

    if (!$domain || !isValidDomain($domain)) {
        sendError('Invalid domain name.');
    }

    // ═══════════════════════════════════════════════════════════════════
    //  Full-response cache (Issue #189) — a hit here skips the ENTIRE lookup
    //  pipeline (WHOIS/RDAP fetch + ~35-check enrichment pipeline), not just
    //  the raw WHOIS text. Keyed by DNT and by response shape (the JSON API
    //  shape carries 'raw'; the HTML-embed shape carries masked/escaped
    //  'whois' instead) so a hit always matches what THIS request expects
    //  back. source=whois requests always bypass the cache (read-side only)
    //  so the diff feature keeps seeing a fresh WHOIS fetch.
    // ═══════════════════════════════════════════════════════════════════
    $fullKey = 'full:' . $domain . ($dnt ? ':dnt' : '') . ($jsonFormat ? ':json' : '');
    if ($sourceParam !== 'whois') {
        $cachedFullRaw = getCached($fullKey);
        if ($cachedFullRaw !== null) {
            $cachedFullResponse = json_decode($cachedFullRaw, true);
            if (is_array($cachedFullResponse)) {
                if (!$dnt) trackLookup('cache_hit', $domain);
                $cachedFullResponse['cached'] = true;
                $cachedFullResponse['verification_token'] = ($domain && session_id())
                    ? generateVerificationToken($domain, session_id())
                    : null;
                $cachedFullResponse['rate_limit'] = ['used' => $rateLimitUsed, 'remaining' => $rateLimitRemaining, 'limit' => $rateLimit];
                // Issue #196 Step 4: additive field — lets a UI that already
                // rendered this cached legacy response start firing
                // `?modules=` follow-up fetches (e.g. modules=score) without
                // an extra modules=core round trip, exempt from rate-limit
                // counting for 180s. Freshly minted on every response (never
                // cached — see the unset() below) since it's a short-lived,
                // per-caller token.
                $cachedFullResponse['lookup_token'] = ($domain && session_id())
                    ? issueLookupToken($domain, resolveLookupTokenBinding($apiKeyConfig, $apiKeyHeader))
                    : null;
                // Issue #198: no wildcard CORS — the same-origin web UI authenticates
                // via the CSRF token (no CORS needed) and API-key clients are
                // server-to-server (CORS is a browser-only concept, so it's moot there).
                sendJson($cachedFullResponse);
            }
        }
    }

    // ─── Lookup pipeline ───
    $whoisText = getCached($domain);
    $fromCache = ($whoisText !== null);
    $dataSource = 'whois';

    if ($fromCache) {
        if (!$dnt) trackLookup('cache_hit', $domain);
    }

    // Try RDAP first (unless source=whois or cached)
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

// Enrichment pipeline defaults (Issue #190) — declared here so the response-array
// assembly below always has a defined value, even when the pipeline is skipped
// for available (unregistered) domains, since the frontend hides these panes anyway.
$emailSecurity = [];
$sslInfo = null;
$registrarReputation = null;
$safeBrowsing = null;
$virusTotal = null;
$hibp = null;
$screenshotUrl = null;
$dnssec = null;
$certTransparency = null;
$domainAgeRisk = null;
$abuseIpDb = null;
$shodan = null;
$phishTank = null;
$urlhaus = null;
$spamhaus = null;
$mtaSts = null;
$bimi = null;
$daneTlsa = null;
$whoisPrivacy = null;
$hostingRisk = null;
$httpHeaders = null;
$redirectChain = null;
$tlsAudit = null;
$caaRecords = null;
$smtpSecurity = null;
$reverseIp = null;
$httpVersions = null;
$ipv6 = null;
$responseTimes = null;
$nsDiversity = null;
$domainSuggestions = [];
$techStack = null;
$robotsTxt = null;
$dnsPropagation = null;
$multiDnsbl = null;
$subdomains = [];
$geolocation = null;

// Enrichment pipeline (Issue #190) — skipped entirely for available/unregistered
// domains, since the frontend hides every enrichment pane in that case anyway.
//
// Issue #196 Step 1: the ~30 per-check blocks that used to sit inline here were
// extracted into includes/modules.php's moduleRegistry()/runModuleChecks(). The
// checks that stay inline below (registrar_reputation, screenshot_url,
// domain_age_risk, whois_privacy, domain_suggestions) are the "core" response
// keys per the Issue #196 plan — they're local/derived-from-existing-data
// computations, not part of the dns/web/email/reputation/subdomains module
// grouping, so runCoreLookup() extraction is deferred to a later step.
if ($availability !== 'available') {

// Registrar reputation check (Issue #51)
$registrarReputation = null;
if (!empty($parsed['Registrar'])) {
    $registrarReputation = checkRegistrarReputation($parsed['Registrar']);
}

// Screenshot URL (Issue #55) — generate if enabled; skip if DNT
$screenshotUrl = null;
if (!$dnt && !$isIpLookup && $domain && !empty($config['screenshot_enabled'])) {
    $screenshotBase = 'https://image.thum.io/get';
    if (!empty($config['screenshot_api_key'])) {
        $screenshotBase .= '/auth/' . urlencode($config['screenshot_api_key']);
    }
    $screenshotUrl = $screenshotBase . '/width/600/' . urlencode('https://' . $domain);
}

// Domain age risk scoring (Issue #95) — uses existing parsed data
$domainAgeRisk = null;
if (!$isIpLookup && !empty($parsed)) {
    $domainAgeRisk = assessDomainAgeRisk($parsed);
}

// WHOIS privacy detection (Issue #104) — uses existing data
$whoisPrivacy = null;
if (!$isIpLookup && $whoisText) {
    $whoisPrivacy = detectWhoisPrivacy($whoisText, $parsed);
}

// Domain suggestions (Issue #116) — only for registered/unavailable domains
$domainSuggestions = [];

// ═══════════════════════════════════════════════════════════════════
//  Module registry enrichment (Issue #196 Step 1)
//
//  Replaces the formerly-inline dns/web/email/reputation/subdomains check
//  blocks with a data-driven loop over includes/modules.php's
//  moduleRegistry(). Each module's gating and function calls are byte-for-
//  byte the same as the code they replace — only the dispatch mechanism
//  changed. See includes/modules.php for the descriptor map and gating
//  logic, and tests/ModulesTest.php for the registry-completeness proof.
// ═══════════════════════════════════════════════════════════════════
$moduleCtx = [
    'domain' => $domain,
    'is_ip'  => $isIpLookup,
    'dns'    => $dns,
    'parsed' => $parsed,
    'dnt'    => $dnt,
    'config' => $config,
];

$dnsModule = runModuleChecks('dns', $moduleCtx);
setModuleCache('dns', $domain, $dnt, $dnsModule); // Issue #196 Step 3: warm the module cache
if (array_key_exists('dnssec', $dnsModule['data'])) { $dnssec = $dnsModule['data']['dnssec']; }
if (array_key_exists('ipv6', $dnsModule['data'])) { $ipv6 = $dnsModule['data']['ipv6']; }
if (array_key_exists('ns_diversity', $dnsModule['data'])) { $nsDiversity = $dnsModule['data']['ns_diversity']; }
if (array_key_exists('dns_propagation', $dnsModule['data'])) { $dnsPropagation = $dnsModule['data']['dns_propagation']; }

$webModule = runModuleChecks('web', $moduleCtx);
setModuleCache('web', $domain, $dnt, $webModule); // Issue #196 Step 3: warm the module cache
if (array_key_exists('ssl', $webModule['data'])) { $sslInfo = $webModule['data']['ssl']; }
if (array_key_exists('http_headers', $webModule['data'])) { $httpHeaders = $webModule['data']['http_headers']; }
if (array_key_exists('tls_audit', $webModule['data'])) { $tlsAudit = $webModule['data']['tls_audit']; }
if (array_key_exists('http_versions', $webModule['data'])) { $httpVersions = $webModule['data']['http_versions']; }
if (array_key_exists('redirect_chain', $webModule['data'])) { $redirectChain = $webModule['data']['redirect_chain']; }
if (array_key_exists('response_times', $webModule['data'])) { $responseTimes = $webModule['data']['response_times']; }
if (array_key_exists('tech_stack', $webModule['data'])) { $techStack = $webModule['data']['tech_stack']; }
if (array_key_exists('robots_txt', $webModule['data'])) { $robotsTxt = $webModule['data']['robots_txt']; }
if (array_key_exists('cert_transparency', $webModule['data'])) { $certTransparency = $webModule['data']['cert_transparency']; }
if (array_key_exists('dane_tlsa', $webModule['data'])) { $daneTlsa = $webModule['data']['dane_tlsa']; }
if (array_key_exists('caa_records', $webModule['data'])) { $caaRecords = $webModule['data']['caa_records']; }

$emailModule = runModuleChecks('email', $moduleCtx);
setModuleCache('email', $domain, $dnt, $emailModule); // Issue #196 Step 3: warm the module cache
if (array_key_exists('email_security', $emailModule['data'])) { $emailSecurity = $emailModule['data']['email_security']; }
if (array_key_exists('mta_sts', $emailModule['data'])) { $mtaSts = $emailModule['data']['mta_sts']; }
if (array_key_exists('bimi', $emailModule['data'])) { $bimi = $emailModule['data']['bimi']; }
if (array_key_exists('smtp_security', $emailModule['data'])) { $smtpSecurity = $emailModule['data']['smtp_security']; }
if (array_key_exists('hibp', $emailModule['data'])) { $hibp = $emailModule['data']['hibp']; }
if (array_key_exists('multi_dnsbl', $emailModule['data'])) { $multiDnsbl = $emailModule['data']['multi_dnsbl']; }
if (array_key_exists('spamhaus', $emailModule['data'])) { $spamhaus = $emailModule['data']['spamhaus']; }

$reputationModule = runModuleChecks('reputation', $moduleCtx);
setModuleCache('reputation', $domain, $dnt, $reputationModule); // Issue #196 Step 3: warm the module cache
if (array_key_exists('safe_browsing', $reputationModule['data'])) { $safeBrowsing = $reputationModule['data']['safe_browsing']; }
if (array_key_exists('virustotal', $reputationModule['data'])) { $virusTotal = $reputationModule['data']['virustotal']; }
if (array_key_exists('phishtank', $reputationModule['data'])) { $phishTank = $reputationModule['data']['phishtank']; }
if (array_key_exists('urlhaus', $reputationModule['data'])) { $urlhaus = $reputationModule['data']['urlhaus']; }
if (array_key_exists('abuseipdb', $reputationModule['data'])) { $abuseIpDb = $reputationModule['data']['abuseipdb']; }
if (array_key_exists('shodan', $reputationModule['data'])) { $shodan = $reputationModule['data']['shodan']; }
if (array_key_exists('geolocation', $reputationModule['data'])) { $geolocation = $reputationModule['data']['geolocation']; }
if (array_key_exists('hosting_risk', $reputationModule['data'])) { $hostingRisk = $reputationModule['data']['hosting_risk']; }

$subdomainsModule = runModuleChecks('subdomains', $moduleCtx);
setModuleCache('subdomains', $domain, $dnt, $subdomainsModule); // Issue #196 Step 3: warm the module cache
if (array_key_exists('subdomains', $subdomainsModule['data'])) { $subdomains = $subdomainsModule['data']['subdomains']; }
if (array_key_exists('reverse_ip', $subdomainsModule['data'])) { $reverseIp = $subdomainsModule['data']['reverse_ip']; }

} // end enrichment pipeline (Issue #190)

// Domain suggestions (Issue #116/#164) — now on-demand only, triggered by separate request
// Automatic suggestions removed to speed up main lookup response

// Security score (Issue #128) — aggregated after all checks
$securityScore = null;
if (!$isIpLookup && $domain) {
    $securityScore = calculateSecurityScore([
        'ssl' => $sslInfo, 'http_headers' => $httpHeaders, 'dnssec' => $dnssec,
        'email_security' => $emailSecurity, 'mta_sts' => $mtaSts,
        'tls_audit' => $tlsAudit, 'spamhaus' => $spamhaus,
        'caa_records' => $caaRecords, 'urlhaus' => $urlhaus,
    ]);
}

// Domain verification token (Issue #136)
$verificationToken = null;
if (!$isIpLookup && $domain && session_id()) {
    $verificationToken = generateVerificationToken($domain, session_id());
}

if ($jsonFormat) {
    // Issue #198: no wildcard CORS — the same-origin web UI authenticates via
    // the CSRF token (no CORS needed) and API-key clients are server-to-server
    // (CORS is a browser-only concept, so it's moot there).
    $response = [
        'domain'       => $domain,
        'is_ip'        => $isIpLookup,
        'availability' => $availability,
        'data_source'  => $dataSource,
        'parsed'       => $parsed,
        'dns'          => $dns,
        'raw'          => $whoisText,
        'cached'       => $fromCache,
        'email_security' => $emailSecurity,
        'ssl' => $sslInfo,
        'geolocation' => $geolocation,
        'subdomains' => $subdomains,
        'registrar_reputation' => $registrarReputation,
        'safe_browsing' => $safeBrowsing,
        'virustotal' => $virusTotal,
        'screenshot_url' => $screenshotUrl,
        'hibp' => $hibp,
        'dnssec' => $dnssec,
        'cert_transparency' => $certTransparency,
        'domain_age_risk' => $domainAgeRisk,
        'abuseipdb' => $abuseIpDb,
        'shodan' => $shodan,
        'phishtank' => $phishTank,
        'urlhaus' => $urlhaus,
        'spamhaus' => $spamhaus,
        'mta_sts' => $mtaSts,
        'bimi' => $bimi,
        'dane_tlsa' => $daneTlsa,
        'whois_privacy' => $whoisPrivacy,
        'hosting_risk' => $hostingRisk,
        'http_headers' => $httpHeaders,
        'redirect_chain' => $redirectChain,
        'tls_audit' => $tlsAudit,
        'caa_records' => $caaRecords,
        'smtp_security' => $smtpSecurity,
        'reverse_ip' => $reverseIp,
        'http_versions' => $httpVersions,
        'ipv6' => $ipv6,
        'response_times' => $responseTimes,
        'ns_diversity' => $nsDiversity,
        'domain_suggestions' => $domainSuggestions,
        'tech_stack' => $techStack,
        'robots_txt' => $robotsTxt,
        'dns_propagation' => $dnsPropagation,
        'multi_dnsbl' => $multiDnsbl,
        'security_score' => $securityScore,
        'verification_token' => $verificationToken,
        // Issue #196 Step 4: additive field — freshly minted here (never
        // cached, see the unset() below) rather than reused from
        // $verificationToken's guard: unlike domain-ownership verification,
        // lookup_token exemption is meaningful for IP lookups too (the
        // email/reputation modules apply to IPs), so it deliberately omits
        // the `!$isIpLookup` check.
        'lookup_token' => ($domain && session_id())
            ? issueLookupToken($domain, resolveLookupTokenBinding($apiKeyConfig, $apiKeyHeader))
            : null,
        'rate_limit' => ['used' => $rateLimitUsed, 'remaining' => $rateLimitRemaining, 'limit' => $rateLimit],
        'dnt' => $dnt,
    ];
    if ($reverseDns) {
        $response['reverse_dns'] = $reverseDns;
    }
    // Full-response cache (Issue #189) — store everything EXCEPT the per-request/
    // per-session fields (verification_token, rate_limit, lookup_token), which
    // are re-injected fresh on every cache hit above.
    if (!$isIpLookup) {
        $responseToCache = $response;
        unset($responseToCache['verification_token'], $responseToCache['rate_limit'], $responseToCache['lookup_token']);
        setCache($fullKey, json_encode($responseToCache));
    }
    sendJson($response);
} else {
    $whoisOutput = '';
    if ($whoisText) {
        $whoisOutput = $whoisText;
        // WHOIS contact masking (Issue #137)
        if (!empty($config['mask_whois_contacts'])) {
            $whoisOutput = preg_replace('/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/', '[email redacted]', $whoisOutput);
            // Issue #218: only redact digit-runs on lines carrying a phone-like
            // label (Phone/Fax/Tel/Telephone). The old unscoped pattern also
            // matched dates (2020-01-15), IPs, and registry IDs on unrelated lines.
            $whoisOutput = preg_replace_callback(
                '/^(.*\b(?:Phone|Fax|Tel)\w*.*)$/mi',
                function ($m) {
                    return preg_replace('/\+?[0-9][\d\s.()-]{7,}/', '[phone redacted]', $m[0]);
                },
                $whoisOutput
            );
        }
    }

    $response = [
        'whois'        => htmlspecialchars($whoisOutput, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        'domain'       => $domain,
        'is_ip'        => $isIpLookup,
        'availability' => $availability,
        'data_source'  => $dataSource,
        'parsed'       => $parsed,
        'dns'          => $dns,
        'cached'       => $fromCache,
        'email_security' => $emailSecurity,
        'ssl' => $sslInfo,
        'geolocation' => $geolocation,
        'subdomains' => $subdomains,
        'registrar_reputation' => $registrarReputation,
        'safe_browsing' => $safeBrowsing,
        'virustotal' => $virusTotal,
        'screenshot_url' => $screenshotUrl,
        'hibp' => $hibp,
        'dnssec' => $dnssec,
        'cert_transparency' => $certTransparency,
        'domain_age_risk' => $domainAgeRisk,
        'abuseipdb' => $abuseIpDb,
        'shodan' => $shodan,
        'phishtank' => $phishTank,
        'urlhaus' => $urlhaus,
        'spamhaus' => $spamhaus,
        'mta_sts' => $mtaSts,
        'bimi' => $bimi,
        'dane_tlsa' => $daneTlsa,
        'whois_privacy' => $whoisPrivacy,
        'hosting_risk' => $hostingRisk,
        'http_headers' => $httpHeaders,
        'redirect_chain' => $redirectChain,
        'tls_audit' => $tlsAudit,
        'caa_records' => $caaRecords,
        'smtp_security' => $smtpSecurity,
        'reverse_ip' => $reverseIp,
        'http_versions' => $httpVersions,
        'ipv6' => $ipv6,
        'response_times' => $responseTimes,
        'ns_diversity' => $nsDiversity,
        'domain_suggestions' => $domainSuggestions,
        'tech_stack' => $techStack,
        'robots_txt' => $robotsTxt,
        'dns_propagation' => $dnsPropagation,
        'multi_dnsbl' => $multiDnsbl,
        'security_score' => $securityScore,
        'verification_token' => $verificationToken,
        // Issue #196 Step 4: additive field — freshly minted here (never
        // cached, see the unset() below) rather than reused from
        // $verificationToken's guard: unlike domain-ownership verification,
        // lookup_token exemption is meaningful for IP lookups too (the
        // email/reputation modules apply to IPs), so it deliberately omits
        // the `!$isIpLookup` check.
        'lookup_token' => ($domain && session_id())
            ? issueLookupToken($domain, resolveLookupTokenBinding($apiKeyConfig, $apiKeyHeader))
            : null,
        'rate_limit' => ['used' => $rateLimitUsed, 'remaining' => $rateLimitRemaining, 'limit' => $rateLimit],
        'dnt' => $dnt,
    ];
    if ($reverseDns) {
        $response['reverse_dns'] = $reverseDns;
    }
    // Full-response cache (Issue #189) — see the matching comment in the $jsonFormat
    // branch above for what's stored and why.
    if (!$isIpLookup) {
        $responseToCache = $response;
        unset($responseToCache['verification_token'], $responseToCache['rate_limit'], $responseToCache['lookup_token']);
        setCache($fullKey, json_encode($responseToCache));
    }
    sendJson($response);
}
