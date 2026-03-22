<?php
/**
 * mwWhoIs Lookup API
 * Handles WHOIS/RDAP lookups, DNS queries, and domain availability detection.
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ─── Shared session config (must match index.php) ───
require_once __DIR__ . DIRECTORY_SEPARATOR . 'session_config.php';

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

// ─── Load functions ───
require_once __DIR__ . DIRECTORY_SEPARATOR . 'functions.php';


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

// CSRF (skip for JSON API requests)
if (!$jsonFormat && !validateCsrfToken()) {
    sendError('Invalid request. Please refresh the page and try again.', 403);
}

// Rate limit (session-based + IP-based)
if (!checkRateLimit() || !checkIpRateLimit()) {
    sendError('Rate limit exceeded. Please wait before trying again.', 429);
}

// Update TLD data (IANA + second-level suffixes, throttled to once per day)
updateTldDataIfNeeded();

// Parse & validate input
$rawDomainInput = '';
if (isset($_POST['domain'])) {
    $rawDomainInput = trim((string)$_POST['domain']);
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

    // ─── Lookup pipeline ───
    $whoisText = getCached($domain);
    $fromCache = ($whoisText !== null);
    $dataSource = 'whois';

    // Try RDAP first (unless source=whois or cached)
    if (!$fromCache && $sourceParam === 'rdap') {
        $rdap = rdapLookup($domain);
        if ($rdap) {
            $dataSource = 'rdap';
            $whoisText = formatRdapResponse($rdap);
        }
    }

    // Fall back to system WHOIS
    if (!$whoisText) {
        $whoisText = shell_exec("whois " . escapeshellarg($domain) . " 2>&1");
        $dataSource = 'whois';
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

// Email security check (Issue #56) — only for domain lookups
$emailSecurity = [];
if (!$isIpLookup && $domain) {
    $emailSecurity = checkEmailSecurity($domain);
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
    ];
    if ($reverseDns) {
        $response['reverse_dns'] = $reverseDns;
    }
    sendJson($response);
} else {
    $whoisOutput = '';
    if ($whoisText) {
        $whoisOutput = $whoisText;
    }

    $response = [
        'whois'        => htmlspecialchars($whoisOutput, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'),
        'is_ip'        => $isIpLookup,
        'availability' => $availability,
        'data_source'  => $dataSource,
        'parsed'       => $parsed,
        'dns'          => $dns,
        'cached'       => $fromCache,
        'email_security' => $emailSecurity,
    ];
    if ($reverseDns) {
        $response['reverse_dns'] = $reverseDns;
    }
    sendJson($response);
}
