<?php
/**
 * mwWhoIs Lookup API
 * Handles WHOIS/RDAP lookups, DNS queries, and domain availability detection.
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ─── Shared session config (must match index.php) ───
require_once __DIR__ . '/session_config.php';

// ─── No-cache headers ───
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Pragma: no-cache");
header("Expires: Thu, 01 Jan 1970 00:00:00 GMT");

// ─── Constants ───
define('IANA_TLD_URL', 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt');
define('IANA_TLD_PATH', __DIR__ . '/tlds.txt');
define('PSL_ICANN_URL', 'https://publicsuffix.org/list/public_suffix_list.dat');
define('SL_SUFFIXES_PATH', __DIR__ . '/second_level_suffixes.txt');
define('TLD_META_PATH', __DIR__ . '/tld_metadata.json');
define('CACHE_DIR', sys_get_temp_dir() . '/mwwhois_cache');
define('CACHE_TTL', 900); // 15 minutes
define('RATE_LIMIT_MAX', 30);
define('RATE_LIMIT_WINDOW', 60);

// ═══════════════════════════════════════════════════════════════════
//  Security helpers
// ═══════════════════════════════════════════════════════════════════

function validateCsrfToken(): bool {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

function checkRateLimit(): bool {
    $now = time();
    if (!isset($_SESSION['rate_limit']) || $now - $_SESSION['rate_limit']['start'] > RATE_LIMIT_WINDOW) {
        $_SESSION['rate_limit'] = ['count' => 0, 'start' => $now];
    }
    $_SESSION['rate_limit']['count']++;
    return $_SESSION['rate_limit']['count'] <= RATE_LIMIT_MAX;
}

// ═══════════════════════════════════════════════════════════════════
//  Result caching
// ═══════════════════════════════════════════════════════════════════

function getCached(string $domain): ?string {
    $file = CACHE_DIR . '/' . md5($domain) . '.json';
    if (!file_exists($file)) return null;
    $data = json_decode(file_get_contents($file), true);
    if (!$data || (time() - $data['ts']) >= CACHE_TTL) return null;
    return $data['result'];
}

function setCache(string $domain, string $result): void {
    if (!is_dir(CACHE_DIR)) @mkdir(CACHE_DIR, 0755, true);
    file_put_contents(CACHE_DIR . '/' . md5($domain) . '.json', json_encode(['ts' => time(), 'result' => $result]));
}

// ═══════════════════════════════════════════════════════════════════
//  TLD & Second-Level Suffix Lists (auto-updating)
// ═══════════════════════════════════════════════════════════════════

/**
 * Updates both lists daily:
 *  1. IANA root zone TLDs (~25KB from data.iana.org)
 *  2. Second-level suffixes extracted from Mozilla PSL ICANN section (~5KB)
 */
function updateTldDataIfNeeded(): void {
    if (file_exists(TLD_META_PATH)) {
        $meta = json_decode(file_get_contents(TLD_META_PATH), true);
        if (isset($meta['checked_at']) && (time() - $meta['checked_at']) < 86400) return;
    }

    $ctx = stream_context_create(['http' => ['timeout' => 5]]);

    // 1. Fetch IANA TLD list
    $tldResponse = @file_get_contents(IANA_TLD_URL, false, $ctx);
    if ($tldResponse !== false) {
        file_put_contents(IANA_TLD_PATH, $tldResponse);
    }

    // 2. Fetch Mozilla PSL → extract ICANN second-level suffixes only
    $pslResponse = @file_get_contents(PSL_ICANN_URL, false, $ctx);
    if ($pslResponse !== false) {
        $suffixes = extractSecondLevelSuffixes($pslResponse);
        file_put_contents(SL_SUFFIXES_PATH, implode("\n", $suffixes));
    }

    file_put_contents(TLD_META_PATH, json_encode(['checked_at' => time()]));
}

/**
 * Parses the Mozilla PSL and extracts only multi-part ICANN suffixes
 * (e.g. co.uk, com.au) — ignores single TLDs and private domains.
 */
function extractSecondLevelSuffixes(string $pslContent): array {
    $suffixes = [];
    $inIcann = false;

    foreach (explode("\n", $pslContent) as $line) {
        $line = trim($line);
        if ($line === '// ===BEGIN ICANN DOMAINS===') { $inIcann = true; continue; }
        if ($line === '// ===END ICANN DOMAINS===') break;
        if (!$inIcann || $line === '' || str_starts_with($line, '//')) continue;

        // Only keep multi-part entries (contain a dot) — skip wildcard/negation entries
        if (str_contains($line, '.') && !str_starts_with($line, '*') && !str_starts_with($line, '!')) {
            $suffixes[] = strtolower($line);
        }
    }
    return array_unique($suffixes);
}

function loadSecondLevelSuffixes(): array {
    if (!file_exists(SL_SUFFIXES_PATH)) return [];
    return array_filter(
        array_map('trim', file(SL_SUFFIXES_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)),
        fn($l) => $l !== ''
    );
}

function extractRegistrableDomain(string $domain): string {
    $parts = explode('.', strtolower($domain));
    if (count($parts) <= 2) return implode('.', $parts);

    $suffixes = loadSecondLevelSuffixes();

    // Check longest match first (3-part, then 2-part suffixes)
    for ($len = min(3, count($parts) - 1); $len >= 2; $len--) {
        $candidate = implode('.', array_slice($parts, -$len));
        if (in_array($candidate, $suffixes)) {
            return implode('.', array_slice($parts, -($len + 1)));
        }
    }

    // Default: last two parts
    return implode('.', array_slice($parts, -2));
}

// ═══════════════════════════════════════════════════════════════════
//  Domain input handling
// ═══════════════════════════════════════════════════════════════════

function sanitizeDomainInput(string $input): string {
    $input = trim($input);
    $input = filter_var($input, FILTER_SANITIZE_URL);
    $host = parse_url($input, PHP_URL_HOST) ?: $input;
    $host = preg_replace('/^www\./i', '', $host);
    return extractRegistrableDomain(strtolower($host));
}

function isValidDomain(string $domain): bool {
    return (bool) preg_match('/^(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,}$/', $domain);
}

// ═══════════════════════════════════════════════════════════════════
//  Availability detection
// ═══════════════════════════════════════════════════════════════════

function detectAvailability(string $text): string {
    // Positive registration indicators take priority
    if (preg_match('/Registrar:\s*\S+/i', $text) ||
        preg_match('/Creat(?:ion|ed) Date:\s*\S+/i', $text) ||
        preg_match('/Registry Domain ID:\s*\S+/i', $text)) {
        return 'registered';
    }
    // Explicit "not found" patterns (anchored to start of line to avoid boilerplate matches)
    $patterns = [
        '/^No match for /mi',
        '/^NOT FOUND\b/mi',
        '/^No Data Found/mi',
        '/^No entries found/mi',
        '/^Domain not found/mi',
        '/^The queried object does not exist/mi',
        '/^This query returned 0 objects/mi',
        '/^Object does not exist/mi',
        '/^Status:\s*free\b/mi',
        '/^%% No entries found/mi',
    ];
    foreach ($patterns as $p) {
        if (preg_match($p, $text)) return 'available';
    }
    return 'registered';
}

// ═══════════════════════════════════════════════════════════════════
//  DNS records
// ═══════════════════════════════════════════════════════════════════

function getDnsRecords(string $domain): array {
    $records = [];
    $typeMap = [
        DNS_A => 'A', DNS_AAAA => 'AAAA', DNS_MX => 'MX',
        DNS_NS => 'NS', DNS_TXT => 'TXT', DNS_CNAME => 'CNAME',
    ];
    foreach ($typeMap as $const => $name) {
        $result = @dns_get_record($domain, $const);
        if (!$result) continue;
        foreach ($result as $rec) {
            $entry = ['type' => $name, 'value' => ''];
            match ($const) {
                DNS_A     => $entry['value'] = $rec['ip'] ?? '',
                DNS_AAAA  => $entry['value'] = $rec['ipv6'] ?? '',
                DNS_MX    => ($entry['value'] = $rec['target'] ?? '') && ($entry['priority'] = $rec['pri'] ?? ''),
                DNS_NS, DNS_CNAME => $entry['value'] = $rec['target'] ?? '',
                DNS_TXT   => $entry['value'] = $rec['txt'] ?? '',
            };
            $records[] = $entry;
        }
    }
    return $records;
}

// ═══════════════════════════════════════════════════════════════════
//  WHOIS field parsing
// ═══════════════════════════════════════════════════════════════════

function parseWhoisFields(string $text): array {
    $fields = [];
    $single = [
        'Domain Name'        => '/Domain Name:\s*(.+)/i',
        'Registrar'          => '/Registrar:\s*(.+)/i',
        'Creation Date'      => '/Creat(?:ion|ed) Date:\s*(.+)/i',
        'Expiry Date'        => '/Expir(?:y|ation) Date:\s*(.+)/i',
        'Updated Date'       => '/Updated Date:\s*(.+)/i',
        'Registrant Org'     => '/Registrant Organi[sz]ation:\s*(.+)/i',
        'Registrant Country' => '/Registrant Country:\s*(.+)/i',
    ];
    foreach ($single as $label => $regex) {
        if (preg_match($regex, $text, $m)) $fields[$label] = trim($m[1]);
    }
    // Multi-value fields
    if (preg_match_all('/Domain Status:\s*(.+)/i', $text, $m)) {
        $fields['Status'] = array_map('trim', $m[1]);
    }
    if (preg_match_all('/Name Server:\s*(.+)/i', $text, $m)) {
        $fields['Name Servers'] = array_map('trim', $m[1]);
    }
    // Expiry countdown
    if (isset($fields['Expiry Date']) && ($t = strtotime($fields['Expiry Date']))) {
        $fields['Expires In'] = (int)ceil(($t - time()) / 86400) . ' days';
    }
    return $fields;
}

// ═══════════════════════════════════════════════════════════════════
//  RDAP lookup
// ═══════════════════════════════════════════════════════════════════

function rdapLookup(string $domain): ?array {
    $url = "https://rdap.org/domain/" . urlencode($domain);

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_HTTPHEADER     => ['Accept: application/rdap+json'],
            CURLOPT_USERAGENT      => 'mwWhoisLookup/0.3',
        ]);
        $response = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($response === false || $code >= 400) return null;
    } else {
        $ctx = stream_context_create(['http' => [
            'header' => "Accept: application/rdap+json\r\n",
            'timeout' => 5, 'follow_location' => 1, 'max_redirects' => 5, 'ignore_errors' => true,
        ]]);
        $response = @file_get_contents($url, false, $ctx);
        if ($response === false) return null;
    }

    $data = json_decode($response, true);
    return ($data && !isset($data['errorCode'])) ? $data : null;
}

function formatRdapResponse(array $rdap): string {
    $lines = [];
    if (isset($rdap['ldhName'])) $lines[] = "Domain Name: " . strtoupper($rdap['ldhName']);
    foreach ($rdap['status'] ?? [] as $s) $lines[] = "Domain Status: $s";
    foreach ($rdap['events'] ?? [] as $e) {
        $lines[] = ucfirst($e['eventAction'] ?? '') . ": " . ($e['eventDate'] ?? '');
    }
    foreach ($rdap['entities'] ?? [] as $entity) {
        $roles = implode(', ', $entity['roles'] ?? []);
        if ($roles) $lines[] = ucfirst($roles) . ": " . ($entity['handle'] ?? '');
        foreach ($entity['vcardArray'][1] ?? [] as $vc) {
            if ($vc[0] === 'fn')  $lines[] = "  Name: " . $vc[3];
            if ($vc[0] === 'org') $lines[] = "  Organization: " . (is_array($vc[3]) ? $vc[3][0] : $vc[3]);
        }
    }
    foreach ($rdap['nameservers'] ?? [] as $ns) $lines[] = "Name Server: " . ($ns['ldhName'] ?? '');
    return implode("\n", $lines);
}

// ═══════════════════════════════════════════════════════════════════
//  JSON response helper
// ═══════════════════════════════════════════════════════════════════

function sendJson(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function sendError(string $message, int $status = 400): void {
    sendJson(['error' => $message], $status);
}

// ═══════════════════════════════════════════════════════════════════
//  Main request handler
// ═══════════════════════════════════════════════════════════════════

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    exit;
}

// Parameters
$jsonFormat = ($_GET['format'] ?? '') === 'json';
$source = strtolower($_GET['source'] ?? $_POST['source'] ?? 'rdap');
if (!in_array($source, ['rdap', 'whois'])) $source = 'rdap';

// CSRF (skip for API requests)
if (!$jsonFormat && !validateCsrfToken()) {
    sendError('Invalid request. Please refresh the page and try again.', 403);
}

// Rate limit
if (!checkRateLimit()) {
    sendError('Rate limit exceeded. Please wait before trying again.', 429);
}

// Update TLD data (IANA + second-level suffixes, throttled to once per day)
updateTldDataIfNeeded();

// Parse & validate domain
$domain = sanitizeDomainInput($_POST['domain'] ?? '');
if (!$domain || !isValidDomain($domain)) {
    sendError('Invalid domain name.');
}

// ─── Lookup pipeline ───
$whoisText = getCached($domain);
$fromCache = ($whoisText !== null);
$dataSource = 'whois';

// Try RDAP first (unless source=whois or cached)
if (!$fromCache && $source === 'rdap') {
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
$availability = $whoisText ? detectAvailability($whoisText) : 'unknown';
$parsed = $whoisText ? parseWhoisFields($whoisText) : [];
$dns = getDnsRecords($domain);

if ($jsonFormat) {
    header('Access-Control-Allow-Origin: *');
    sendJson([
        'domain'       => $domain,
        'availability' => $availability,
        'data_source'  => $dataSource,
        'parsed'       => $parsed,
        'dns'          => $dns,
        'raw'          => $whoisText ?: null,
        'cached'       => $fromCache,
    ]);
} else {
    sendJson([
        'whois'        => htmlspecialchars($whoisText ?: ''),
        'availability' => $availability,
        'data_source'  => $dataSource,
        'parsed'       => $parsed,
        'dns'          => $dns,
        'cached'       => $fromCache,
    ]);
}
