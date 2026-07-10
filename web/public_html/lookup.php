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


// ═══════════════════════════════════════════════════════════════════
//  On-demand domain suggestions endpoint (Issue #164)
// ═══════════════════════════════════════════════════════════════════

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['suggest']) && $_GET['suggest'] === '1') {
    header('Content-Type: application/json');
    $suggestDomain = isset($_POST['domain']) ? trim((string)$_POST['domain']) : '';
    $suggestDomain = sanitizeDomainInput($suggestDomain);
    if (!$suggestDomain || !isValidDomain($suggestDomain)) {
        echo json_encode(['suggestions' => [], 'grid' => null]);
        exit;
    }
    // Rate-limit the suggest endpoint just like the main lookup.
    if (!checkRateLimit() || !checkIpRateLimit()) {
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

// CSRF (skip for JSON API requests and API key users)
if (!$jsonFormat && !$apiKeyConfig && !validateCsrfToken()) {
    sendError('Invalid request. Please refresh the page and try again.', 403);
}

// Rate limit — use API key tier limit if applicable
$rateLimit = $apiKeyConfig ? getApiKeyRateLimit($apiKeyConfig) : RATE_LIMIT_MAX;
if (!checkRateLimit($rateLimit) || !checkIpRateLimit($rateLimit)) {
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
                if ($jsonFormat) {
                    header('Access-Control-Allow-Origin: *');
                    header('Access-Control-Allow-Methods: POST');
                    header('Access-Control-Allow-Headers: Content-Type');
                }
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
if ($availability !== 'available') {

// Email security check (Issue #56) — only for domain lookups
if (!$isIpLookup && $domain) {
    $emailSecurity = checkEmailSecurity($domain);
}

// SSL/TLS certificate info (Issue #19) — only for domain lookups
$sslInfo = null;
if (!$isIpLookup && $domain) {
    $sslInfo = getSslInfo($domain);
}

// Registrar reputation check (Issue #51)
$registrarReputation = null;
if (!empty($parsed['Registrar'])) {
    $registrarReputation = checkRegistrarReputation($parsed['Registrar']);
}

// Google Safe Browsing (Issue #52) — only if API key configured; skip if DNT
$safeBrowsing = null;
if (!$dnt && !$isIpLookup && $domain && !empty($config['safe_browsing_api_key'])) {
    $safeBrowsing = checkSafeBrowsing($domain, $config['safe_browsing_api_key']);
}

// VirusTotal (Issue #53) — only if API key configured; skip if DNT
$virusTotal = null;
if (!$dnt && !$isIpLookup && $domain && !empty($config['virustotal_api_key'])) {
    $virusTotal = checkVirusTotal($domain, $config['virustotal_api_key']);
}

// Have I Been Pwned (Issue #65) — only if API key configured; skip if DNT
$hibp = null;
if (!$dnt && !$isIpLookup && $domain && !empty($config['hibp_api_key'])) {
    $hibp = checkHibpDomain($domain, $config['hibp_api_key']);
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

// DNSSEC check (Issue #93) — no API key needed
$dnssec = null;
if (!$isIpLookup && $domain) {
    $dnssec = checkDnssec($domain);
}

// Certificate Transparency (Issue #94) — skip if DNT (third-party request)
$certTransparency = null;
if (!$dnt && !$isIpLookup && $domain) {
    $certTransparency = checkCertTransparency($domain);
}

// Domain age risk scoring (Issue #95) — uses existing parsed data
$domainAgeRisk = null;
if (!$isIpLookup && !empty($parsed)) {
    $domainAgeRisk = assessDomainAgeRisk($parsed);
}

// AbuseIPDB (Issue #96) — only if API key configured; skip if DNT
$abuseIpDb = null;
if (!$dnt && !empty($config['abuseipdb_api_key'])) {
    $checkIp = $isIpLookup ? $domain : null;
    if (!$checkIp && !empty($dns)) {
        foreach ($dns as $rec) {
            if ($rec['type'] === 'A' && !empty($rec['value'])) { $checkIp = $rec['value']; break; }
        }
    }
    if ($checkIp) {
        $abuseIpDb = checkAbuseIPDB($checkIp, $config['abuseipdb_api_key']);
    }
}

// Shodan (Issue #97) — only if API key configured; skip if DNT
$shodan = null;
if (!$dnt && !empty($config['shodan_api_key'])) {
    $checkIp = $isIpLookup ? $domain : null;
    if (!$checkIp && !empty($dns)) {
        foreach ($dns as $rec) {
            if ($rec['type'] === 'A' && !empty($rec['value'])) { $checkIp = $rec['value']; break; }
        }
    }
    if ($checkIp) {
        $shodan = checkShodan($checkIp, $config['shodan_api_key']);
    }
}

// PhishTank (Issue #98) — only if API key configured; skip if DNT
$phishTank = null;
if (!$dnt && !$isIpLookup && $domain && !empty($config['phishtank_api_key'])) {
    $phishTank = checkPhishTank($domain, $config['phishtank_api_key']);
}

// URLhaus (Issue #99) — free, no API key; skip if DNT
$urlhaus = null;
if (!$dnt && !$isIpLookup && $domain) {
    $urlhaus = checkUrlhaus($domain);
}

// Spamhaus DNSBL (Issue #100) — derived from the multi-DNSBL result below (Issue #191);
// checkSpamhaus() used to run a separate, duplicate zen.spamhaus.org query.

// MTA-STS (Issue #101) — no API key needed
$mtaSts = null;
if (!$isIpLookup && $domain) {
    $mtaSts = checkMtaSts($domain);
}

// BIMI (Issue #102) — no API key needed
$bimi = null;
if (!$isIpLookup && $domain) {
    $bimi = checkBimi($domain);
}

// DANE/TLSA (Issue #103) — no API key needed
$daneTlsa = null;
if (!$isIpLookup && $domain) {
    $daneTlsa = checkDaneTlsa($domain);
}

// WHOIS privacy detection (Issue #104) — uses existing data
$whoisPrivacy = null;
if (!$isIpLookup && $whoisText) {
    $whoisPrivacy = detectWhoisPrivacy($whoisText, $parsed);
}

// Hosting country risk (Issue #105) — uses existing geolocation data
$hostingRisk = null;

// HTTP security headers audit (Issue #106) — skip if DNT
$httpHeaders = null;
if (!$dnt && !$isIpLookup && $domain) {
    $httpHeaders = auditHttpHeaders($domain);
}

// Redirect chain (Issue #107) — skip if DNT
$redirectChain = null;
if (!$dnt && !$isIpLookup && $domain) {
    $redirectChain = detectRedirectChain($domain);
}

// TLS audit (Issue #108) — skip if DNT
$tlsAudit = null;
if (!$dnt && !$isIpLookup && $domain) {
    $tlsAudit = auditTlsVersions($domain);
}

// CAA records (Issue #109) — no API key needed
$caaRecords = null;
if (!$isIpLookup && $domain) {
    $caaRecords = checkCaaRecords($domain);
}

// SMTP security (Issue #110) — no API key needed
$smtpSecurity = null;
if (!$isIpLookup && $domain) {
    $smtpSecurity = checkSmtpSecurity($domain);
}

// Reverse IP (Issue #111) — skip if DNT (third-party API)
$reverseIp = null;
if (!$dnt && !empty($dns)) {
    foreach ($dns as $rec) {
        if ($rec['type'] === 'A' && !empty($rec['value'])) {
            $reverseIp = reverseIpLookup($rec['value']);
            break;
        }
    }
}

// HTTP version check (Issue #112) — skip if DNT
$httpVersions = null;
if (!$dnt && !$isIpLookup && $domain) {
    $httpVersions = checkHttpVersions($domain);
}

// IPv6 readiness (Issue #113) — no API key needed
$ipv6 = null;
if (!$isIpLookup && $domain) {
    $ipv6 = checkIpv6Readiness($domain);
}

// Response times (Issue #114) — skip if DNT
$responseTimes = null;
if (!$dnt && !$isIpLookup && $domain) {
    $responseTimes = measureResponseTimes($domain);
}

// NS diversity (Issue #115) — no API key needed
$nsDiversity = null;
if (!$isIpLookup && $domain) {
    $nsDiversity = checkNsDiversity($domain);
}

// Domain suggestions (Issue #116) — only for registered/unavailable domains
$domainSuggestions = [];

// Technology stack detection (Issue #124) — skip if DNT
$techStack = null;
if (!$dnt && !$isIpLookup && $domain) {
    $techStack = detectTechStack($domain);
}

// Robots.txt & sitemap analysis (Issue #125) — skip if DNT
$robotsTxt = null;
if (!$dnt && !$isIpLookup && $domain) {
    $robotsTxt = analyseRobotsTxt($domain);
}

// DNS propagation (Issue #126)
$dnsPropagation = null;
if (!$isIpLookup && $domain) {
    $dnsPropagation = checkDnsPropagation($domain);
}

// Multi-DNSBL (Issue #133) — replaces single Spamhaus check
$multiDnsbl = null;
if (!empty($dns)) {
    foreach ($dns as $rec) {
        if ($rec['type'] === 'A' && !empty($rec['value'])) {
            $multiDnsbl = checkMultiDnsbl($rec['value']);
            break;
        }
    }
} elseif ($isIpLookup) {
    $multiDnsbl = checkMultiDnsbl($domain);
}

// Spamhaus (Issue #100/#191) — derived from the zen.spamhaus.org entry already present in
// $multiDnsbl, instead of running checkSpamhaus() as a second, duplicate DNSBL query.
// Mirrors checkSpamhaus()'s original ['listed' => bool, 'lists' => [...]] shape so
// calculateSecurityScore() and the frontend's data.spamhaus.listed/.lists[].label reads
// keep working unchanged.
if ($multiDnsbl !== null) {
    $zenEntry = null;
    foreach ($multiDnsbl['lists'] as $entry) {
        if (($entry['zone'] ?? '') === 'zen.spamhaus.org') {
            $zenEntry = $entry;
            break;
        }
    }
    $spamhaus = [
        'listed' => $zenEntry !== null,
        'lists'  => $zenEntry !== null ? [$zenEntry] : [],
    ];
}

// Subdomain discovery (Issue #46) — only for domain lookups
$subdomains = [];
if (!$isIpLookup && $domain) {
    $subdomains = discoverSubdomains($domain);
}

// IP geolocation (Issue #18) — for first A record, or for IP lookups; skip if DNT
$geolocation = null;
if (!$dnt) {
    if ($isIpLookup) {
        $geolocation = getIpGeolocation($domain);
    } elseif (!empty($dns)) {
        foreach ($dns as $record) {
            if ($record['type'] === 'A' && !empty($record['value'])) {
                $geolocation = getIpGeolocation($record['value']);
                break;
            }
        }
    }
}

// Hosting country risk (Issue #105) — computed after geolocation
$hostingRisk = assessHostingRisk($geolocation);

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
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST');
    header('Access-Control-Allow-Headers: Content-Type');
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
        'rate_limit' => ['used' => $rateLimitUsed, 'remaining' => $rateLimitRemaining, 'limit' => $rateLimit],
        'dnt' => $dnt,
    ];
    if ($reverseDns) {
        $response['reverse_dns'] = $reverseDns;
    }
    // Full-response cache (Issue #189) — store everything EXCEPT the per-request/
    // per-session fields (verification_token, rate_limit), which are re-injected
    // fresh on every cache hit above.
    if (!$isIpLookup) {
        $responseToCache = $response;
        unset($responseToCache['verification_token'], $responseToCache['rate_limit']);
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
            $whoisOutput = preg_replace('/\+?[0-9][\d\s.()-]{7,}/', '[phone redacted]', $whoisOutput);
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
        unset($responseToCache['verification_token'], $responseToCache['rate_limit']);
        setCache($fullKey, json_encode($responseToCache));
    }
    sendJson($response);
}
