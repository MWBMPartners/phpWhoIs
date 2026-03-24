<?php
/**
 * mwWhoIs — Core functions.
 * Extracted from lookup.php for testability.
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ═══════════════════════════════════════════════════════════════════
//  Logging (Issue #43)
// ═══════════════════════════════════════════════════════════════════

/**
 * Log a message to the application error log.
 * Creates the logs directory if it doesn't exist.
 */
function appLog(string $message, string $level = 'ERROR'): void {
    $logDir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }

    $logFile = $logDir . DIRECTORY_SEPARATOR . 'error.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'CLI';
    $entry = "[{$timestamp}] [{$level}] [{$ip}] {$message}" . PHP_EOL;

    @file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}


// ═══════════════════════════════════════════════════════════════════
//  Domain ownership verification (Issue #64)
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate a DNS verification token for domain ownership.
 * The token should be added as a TXT record at _mwwhois-verify.{domain}.
 *
 * @param  string $domain     The domain to verify
 * @param  string $sessionId  Session or user identifier
 * @return string             The verification token
 */
function generateVerificationToken(string $domain, string $sessionId): string {
    return 'mwwhois-verify=' . hash('sha256', $domain . $sessionId . 'mwwhois-salt');
}

/**
 * Check if a domain has the verification TXT record.
 *
 * @param  string $domain  The domain to verify
 * @param  string $token   The expected token value
 * @return bool            True if verified
 */
function verifyDomainOwnership(string $domain, string $token): bool {
    $records = @dns_get_record('_mwwhois-verify.' . $domain, DNS_TXT);
    if (!$records) {
        return false;
    }

    foreach ($records as $record) {
        if (isset($record['txt']) && trim($record['txt']) === $token) {
            return true;
        }
    }

    return false;
}


// ═══════════════════════════════════════════════════════════════════
//  API key management (Issue #61)
// ═══════════════════════════════════════════════════════════════════

/**
 * Load API keys from storage.
 * Keys file format: { "key_hash": { "tier": "free|premium", "rate_limit": 30, "created": "...", "label": "..." } }
 */
function loadApiKeys(): array {
    if (!defined('CACHE_DIR')) {
        return [];
    }
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . 'api_keys.json';
    if (!file_exists($file)) {
        return [];
    }
    $keys = json_decode(file_get_contents($file), true);
    return is_array($keys) ? $keys : [];
}

/**
 * Validate an API key and return its config, or null if invalid.
 */
function validateApiKey(string $key): ?array {
    $keys = loadApiKeys();
    $hash = hash('sha256', $key);
    return isset($keys[$hash]) ? $keys[$hash] : null;
}

/**
 * Get rate limit for an API key tier.
 */
function getApiKeyRateLimit(?array $keyConfig): int {
    if (!$keyConfig) {
        return RATE_LIMIT_MAX; // Default: 30/min
    }
    return isset($keyConfig['rate_limit']) ? (int)$keyConfig['rate_limit'] : RATE_LIMIT_MAX;
}


// ═══════════════════════════════════════════════════════════════════
//  Lookup statistics tracking (Issue #60)
// ═══════════════════════════════════════════════════════════════════

function trackLookup(string $type, string $domain = ''): void {
    if (!defined('CACHE_DIR')) {
        return;
    }
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . 'lookup_stats.json';
    $stats = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    if (!$stats) {
        $stats = ['total' => 0, 'cache_hits' => 0, 'rdap' => 0, 'whois' => 0, 'errors' => 0, 'popular_domains' => []];
    }

    $stats['total'] = ($stats['total'] ?? 0) + 1;
    if ($type === 'cache_hit') {
        $stats['cache_hits'] = ($stats['cache_hits'] ?? 0) + 1;
    }
    if ($type === 'rdap') {
        $stats['rdap'] = ($stats['rdap'] ?? 0) + 1;
    }
    if ($type === 'whois') {
        $stats['whois'] = ($stats['whois'] ?? 0) + 1;
    }
    if ($type === 'error') {
        $stats['errors'] = ($stats['errors'] ?? 0) + 1;
    }

    if ($domain) {
        if (!isset($stats['popular_domains'])) {
            $stats['popular_domains'] = [];
        }
        $stats['popular_domains'][$domain] = ($stats['popular_domains'][$domain] ?? 0) + 1;
        arsort($stats['popular_domains']);
        $stats['popular_domains'] = array_slice($stats['popular_domains'], 0, 100, true);
    }

    @file_put_contents($file, json_encode($stats), LOCK_EX);
}


// ═══════════════════════════════════════════════════════════════════
//  Security helpers
// ═══════════════════════════════════════════════════════════════════

function validateCsrfToken(): bool {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

/**
 * Session-based rate limiting (per-user).
 */
function checkRateLimit(): bool {
    $now = time();

    if (!isset($_SESSION['rate_limit']) || ($now - $_SESSION['rate_limit']['start']) > RATE_LIMIT_WINDOW) {
        $_SESSION['rate_limit'] = ['count' => 0, 'start' => $now];
    }

    $_SESSION['rate_limit']['count']++;

    return $_SESSION['rate_limit']['count'] <= RATE_LIMIT_MAX;
}

/**
 * IP-based rate limiting (Issue #22).
 * Uses file-based storage in the cache directory.
 * Harder to bypass than session-based limiting.
 */
function checkIpRateLimit(): bool {
    // Use REMOTE_ADDR as primary (cannot be spoofed)
    // Only use X-Forwarded-For if behind a trusted proxy
    $ip = '';
    if (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    $ip = trim($ip);
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return true;
    }

    $rateLimitDir = CACHE_DIR . DIRECTORY_SEPARATOR . 'rate_limits';
    if (!is_dir($rateLimitDir)) {
        @mkdir($rateLimitDir, 0755, true);
    }

    // Use hashed IP as filename (privacy + filesystem safety)
    $file = $rateLimitDir . DIRECTORY_SEPARATOR . md5($ip) . '.json';
    $now = time();
    $data = null;

    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
    }

    // Reset if window expired or invalid data
    if (!$data || !isset($data['start']) || ($now - $data['start']) > RATE_LIMIT_WINDOW) {
        $data = ['count' => 0, 'start' => $now];
    }

    $data['count']++;
    file_put_contents($file, json_encode($data));

    // Clean up old rate limit files periodically (1 in 100 chance)
    if (rand(1, 100) === 1) {
        cleanExpiredRateLimits($rateLimitDir);
    }

    return $data['count'] <= RATE_LIMIT_MAX;
}

/**
 * Remove expired rate limit files.
 */
function cleanExpiredRateLimits(string $dir): void {
    $files = glob($dir . DIRECTORY_SEPARATOR . '*.json');
    if (!$files) {
        return;
    }

    $now = time();
    foreach ($files as $file) {
        $data = json_decode(file_get_contents($file), true);
        if (!$data || !isset($data['start']) || ($now - $data['start']) > RATE_LIMIT_WINDOW * 2) {
            @unlink($file);
        }
    }
}

/**
 * Validate that input does not exceed maximum allowed size.
 * Prevents memory exhaustion from oversized POST data.
 */
function validateInputSize(): bool {
    $contentLength = 0;
    if (isset($_SERVER['CONTENT_LENGTH'])) {
        $contentLength = (int)$_SERVER['CONTENT_LENGTH'];
    }

    if ($contentLength > MAX_POST_SIZE) {
        return false;
    }

    return true;
}


// ═══════════════════════════════════════════════════════════════════
//  Result caching (Issue #57 — Redis/Memcached with file fallback)
// ═══════════════════════════════════════════════════════════════════

/**
 * Get a cache backend instance. Tries Redis, then Memcached, then falls back to file.
 * Returns: 'redis', 'memcached', or 'file'.
 */
function getCacheBackend() {
    static $backend = null;
    static $conn = null;

    if ($backend !== null) {
        return ['type' => $backend, 'conn' => $conn];
    }

    // Try Redis
    if (class_exists('Redis')) {
        try {
            $redis = new Redis();
            $host = defined('CACHE_REDIS_HOST') ? CACHE_REDIS_HOST : '127.0.0.1';
            $port = defined('CACHE_REDIS_PORT') ? CACHE_REDIS_PORT : 6379;
            if (@$redis->connect($host, $port, 1)) {
                $backend = 'redis';
                $conn = $redis;
                return ['type' => $backend, 'conn' => $conn];
            }
        } catch (\Exception $e) {
            // Fall through
        }
    }

    // Try Memcached
    if (class_exists('Memcached')) {
        try {
            $mc = new Memcached();
            $host = defined('CACHE_MEMCACHED_HOST') ? CACHE_MEMCACHED_HOST : '127.0.0.1';
            $port = defined('CACHE_MEMCACHED_PORT') ? CACHE_MEMCACHED_PORT : 11211;
            $mc->addServer($host, $port);
            // Test connection
            $mc->getVersion();
            if ($mc->getResultCode() === Memcached::RES_SUCCESS) {
                $backend = 'memcached';
                $conn = $mc;
                return ['type' => $backend, 'conn' => $conn];
            }
        } catch (\Exception $e) {
            // Fall through
        }
    }

    $backend = 'file';
    $conn = null;
    return ['type' => $backend, 'conn' => $conn];
}

function getCached(string $domain): ?string {
    $cache = getCacheBackend();
    $key = 'mwwhois:' . md5($domain);

    if ($cache['type'] === 'redis') {
        $val = $cache['conn']->get($key);
        return $val !== false ? $val : null;
    }

    if ($cache['type'] === 'memcached') {
        $val = $cache['conn']->get($key);
        return $cache['conn']->getResultCode() === Memcached::RES_SUCCESS ? $val : null;
    }

    // File fallback
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';

    if (!file_exists($file)) {
        return null;
    }

    $data = json_decode(file_get_contents($file), true);

    if (!$data || (time() - $data['ts']) >= CACHE_TTL) {
        return null;
    }

    return $data['result'];
}

function setCache(string $domain, string $result): void {
    $cache = getCacheBackend();
    $key = 'mwwhois:' . md5($domain);

    if ($cache['type'] === 'redis') {
        $cache['conn']->setex($key, CACHE_TTL, $result);
        return;
    }

    if ($cache['type'] === 'memcached') {
        $cache['conn']->set($key, $result, CACHE_TTL);
        return;
    }

    // File fallback
    if (!is_dir(CACHE_DIR)) {
        @mkdir(CACHE_DIR, 0755, true);
    }

    $cacheFile = CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';
    file_put_contents($cacheFile, json_encode(['ts' => time(), 'result' => $result]));
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
        if (isset($meta['checked_at']) && (time() - $meta['checked_at']) < 86400) {
            return;
        }
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

        if ($line === '// ===BEGIN ICANN DOMAINS===') {
            $inIcann = true;
            continue;
        }

        if ($line === '// ===END ICANN DOMAINS===') {
            break;
        }

        if (!$inIcann || $line === '' || str_starts_with($line, '//')) {
            continue;
        }

        // Only keep multi-part entries (contain a dot) — skip wildcard/negation entries
        if (str_contains($line, '.')  && !str_starts_with($line, '*') && !str_starts_with($line, '!')) {
            $suffixes[] = strtolower($line);
        }
    }

    return array_unique($suffixes);
}

function loadSecondLevelSuffixes(): array {
    if (!file_exists(SL_SUFFIXES_PATH)) {
        return [];
    }

    $lines = file(SL_SUFFIXES_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $trimmed = array_map('trim', $lines);

    return array_filter($trimmed, function($line) {
        return $line !== '';
    });
}

function extractRegistrableDomain(string $domain): string {
    $parts = explode('.', strtolower($domain));

    if (count($parts) <= 2) {
        return implode('.', $parts);
    }

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
//  IP / Reverse DNS (Issue #45)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check if input is an IP address (v4 or v6).
 */
function isIpAddress(string $input): bool {
    return filter_var($input, FILTER_VALIDATE_IP) ;
}

/**
 * Perform reverse DNS lookup for an IP address.
 * Returns PTR hostname or null.
 */
function reverseDnsLookup(string $ip): ?string {
    $hostname = gethostbyaddr($ip);
    if ($hostname === false || $hostname === $ip) {
        return null;
    }
    return $hostname;
}

/**
 * Get WHOIS info for an IP address.
 */
function ipWhoisLookup(string $ip): ?string {
    $escapedIp = escapeshellarg($ip);
    $result = shell_exec("whois {$escapedIp} 2>&1");
    if ($result) {
        return $result;
    }
    return null;
}


// ═══════════════════════════════════════════════════════════════════
//  Domain input handling
// ═══════════════════════════════════════════════════════════════════

function sanitizeDomainInput(string $input): string {
    $input = trim($input);

    // Reject excessively long input
    if (strlen($input) > MAX_DOMAIN_LENGTH) {
        return '';
    }

    // Strip null bytes (injection vector)
    $input = str_replace("\0", '', $input);

    $input = filter_var($input, FILTER_SANITIZE_URL);

    $host = parse_url($input, PHP_URL_HOST);
    if (!$host) {
        $host = $input;
    }

    $host = preg_replace('/^www\./i', '', $host);

    return extractRegistrableDomain(strtolower($host));
}

function isValidDomain(string $domain): bool {
    // Length check
    if (strlen($domain) === 0 || strlen($domain) > MAX_DOMAIN_LENGTH) {
        return false;
    }

    // Must not contain shell-dangerous characters
    if (preg_match('/[;&|`$(){}\\\\<>\'"!#]/', $domain)) {
        return false;
    }

    // Standard domain format validation (no leading/trailing hyphens per label)
    return (bool) preg_match('/^(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $domain);
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
        if (preg_match($p, $text)) {
            return 'available';
        }
    }

    return 'registered';
}


// ═══════════════════════════════════════════════════════════════════
//  DNS records
// ═══════════════════════════════════════════════════════════════════

function getDnsRecords(string $domain): array {
    $records = [];
    $typeMap = [
        DNS_A => 'A',
        DNS_AAAA => 'AAAA',
        DNS_MX => 'MX',
        DNS_NS => 'NS',
        DNS_TXT => 'TXT',
        DNS_CNAME => 'CNAME',
    ];

    foreach ($typeMap as $const => $name) {
        $result = @dns_get_record($domain, $const);

        if (!$result) {
            continue;
        }

        foreach ($result as $rec) {
            $entry = ['type' => $name, 'value' => ''];

            switch ($const) {
                case DNS_A:
                    if (isset($rec['ip'])) {
                        $entry['value'] = $rec['ip'];
                    }
                    break;
                case DNS_AAAA:
                    if (isset($rec['ipv6'])) {
                        $entry['value'] = $rec['ipv6'];
                    }
                    break;
                case DNS_MX:
                    if (isset($rec['target'])) {
                        $entry['value'] = $rec['target'];
                    }
                    if (isset($rec['pri'])) {
                        $entry['priority'] = $rec['pri'];
                    }
                    break;
                case DNS_NS:
                case DNS_CNAME:
                    if (isset($rec['target'])) {
                        $entry['value'] = $rec['target'];
                    }
                    break;
                case DNS_TXT:
                    if (isset($rec['txt'])) {
                        $entry['value'] = $rec['txt'];
                    }
                    break;
            }

            $records[] = $entry;
        }
    }

    return $records;
}


// ═══════════════════════════════════════════════════════════════════
//  Email security check — DMARC/SPF/DKIM (Issue #56)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check email security posture by examining DNS TXT records.
 */
function checkEmailSecurity(string $domain): array {
    $result = [
        'spf' => ['found' => false, 'record' => null, 'status' => 'missing'],
        'dmarc' => ['found' => false, 'record' => null, 'status' => 'missing'],
        'dkim' => ['found' => false, 'status' => 'unknown'],
    ];

    // SPF — look in TXT records for the domain
    $txtRecords = @dns_get_record($domain, DNS_TXT);
    if ($txtRecords) {
        foreach ($txtRecords as $rec) {
            if (isset($rec['txt']) && str_starts_with(strtolower($rec['txt']), 'v=spf1')) {
                $result['spf']['found'] = true;
                $result['spf']['record'] = $rec['txt'];
                $result['spf']['status'] = 'configured';
                break;
            }
        }
    }

    // DMARC — look in TXT records for _dmarc.domain
    $dmarcRecords = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
    if ($dmarcRecords) {
        foreach ($dmarcRecords as $rec) {
            if (isset($rec['txt']) && str_starts_with(strtolower($rec['txt']), 'v=dmarc1')) {
                $result['dmarc']['found'] = true;
                $result['dmarc']['record'] = $rec['txt'];

                // Check policy
                if (stripos($rec['txt'], 'p=reject') !== false) {
                    $result['dmarc']['status'] = 'strict (reject)';
                } elseif (stripos($rec['txt'], 'p=quarantine') !== false) {
                    $result['dmarc']['status'] = 'moderate (quarantine)';
                } elseif (stripos($rec['txt'], 'p=none') !== false) {
                    $result['dmarc']['status'] = 'monitor only (none)';
                } else {
                    $result['dmarc']['status'] = 'configured';
                }
                break;
            }
        }
    }

    // DKIM — check common selectors
    $dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim'];
    foreach ($dkimSelectors as $selector) {
        $dkimRecords = @dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
        if ($dkimRecords) {
            foreach ($dkimRecords as $rec) {
                if (isset($rec['txt']) && stripos($rec['txt'], 'v=DKIM1') !== false) {
                    $result['dkim']['found'] = true;
                    $result['dkim']['selector'] = $selector;
                    $result['dkim']['status'] = 'configured (selector: ' . $selector . ')';
                    break 2;
                }
            }
        }
    }

    if (!$result['dkim']['found']) {
        $result['dkim']['status'] = 'not found (checked common selectors)';
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  IP Geolocation (Issue #18)
// ═══════════════════════════════════════════════════════════════════

/**
 * Get geolocation info for an IP address using ip-api.com (free, no key needed).
 * Rate limit: 45 requests/minute.
 */
function getIpGeolocation(string $ip): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $ctx = stream_context_create(['http' => ['timeout' => 3]]);
    $response = @file_get_contents(
        'http://ip-api.com/json/' . urlencode($ip) . '?fields=status,country,countryCode,region,city,isp,org,as',
        false,
        $ctx
    );

    if ($response === false) {
        return null;
    }

    $data = json_decode($response, true);
    if (!$data || $data['status'] !== 'success') {
        return null;
    }

    return [
        'country' => isset($data['country']) ? $data['country'] : '',
        'country_code' => isset($data['countryCode']) ? $data['countryCode'] : '',
        'region' => isset($data['region']) ? $data['region'] : '',
        'city' => isset($data['city']) ? $data['city'] : '',
        'isp' => isset($data['isp']) ? $data['isp'] : '',
        'org' => isset($data['org']) ? $data['org'] : '',
        'as' => isset($data['as']) ? $data['as'] : '',
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  SSL/TLS certificate info (Issue #19)
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch SSL certificate info for a domain.
 */
function getSslInfo(string $domain): ?array {
    $ctx = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
        ],
    ]);

    $client = @stream_socket_client(
        "ssl://{$domain}:443",
        $errno,
        $errstr,
        5,
        STREAM_CLIENT_CONNECT,
        $ctx
    );

    if (!$client) {
        return null;
    }

    $params = stream_context_get_params($client);
    fclose($client);

    if (!isset($params['options']['ssl']['peer_certificate'])) {
        return null;
    }

    $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
    if (!$cert) {
        return null;
    }

    $result = [
        'subject' => isset($cert['subject']['CN']) ? $cert['subject']['CN'] : '',
        'issuer' => isset($cert['issuer']['O']) ? $cert['issuer']['O'] : (isset($cert['issuer']['CN']) ? $cert['issuer']['CN'] : ''),
        'valid_from' => date('Y-m-d H:i:s', $cert['validFrom_time_t']),
        'valid_to' => date('Y-m-d H:i:s', $cert['validTo_time_t']),
        'serial' => isset($cert['serialNumberHex']) ? $cert['serialNumberHex'] : '',
    ];

    // Days until expiry
    $expiryTime = $cert['validTo_time_t'];
    $daysLeft = (int)ceil(($expiryTime - time()) / 86400);
    $result['expires_in'] = $daysLeft . ' days';
    $result['expired'] = ($daysLeft <= 0);

    // SAN (Subject Alternative Names)
    if (isset($cert['extensions']['subjectAltName'])) {
        $sans = array_map('trim', explode(',', $cert['extensions']['subjectAltName']));
        $result['san'] = array_map(function($s) {
            return str_replace('DNS:', '', $s);
        }, $sans);
    }

    return $result;
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
        if (preg_match($regex, $text, $m)) {
            $fields[$label] = trim($m[1]);
        }
    }

    // Multi-value fields
    if (preg_match_all('/Domain Status:\s*(.+)/i', $text, $m)) {
        $fields['Status'] = array_map('trim', $m[1]);
    }

    if (preg_match_all('/Name Server:\s*(.+)/i', $text, $m)) {
        $fields['Name Servers'] = array_map('trim', $m[1]);
    }

    // Domain age (Issue #20)
    if (isset($fields['Creation Date'])) {
        $creationTime = strtotime($fields['Creation Date']);
        if ($creationTime) {
            $now = new DateTime();
            $created = new DateTime('@' . $creationTime);
            $diff = $created->diff($now);

            $ageParts = [];
            if ($diff->y > 0) {
                $ageParts[] = $diff->y . ' year' . ($diff->y !== 1 ? 's' : '');
            }
            if ($diff->m > 0) {
                $ageParts[] = $diff->m . ' month' . ($diff->m !== 1 ? 's' : '');
            }
            if (empty($ageParts) && $diff->d > 0) {
                $ageParts[] = $diff->d . ' day' . ($diff->d !== 1 ? 's' : '');
            }

            if (!empty($ageParts)) {
                $fields['Domain Age'] = implode(', ', $ageParts);
            }
        }
    }

    // Expiry countdown
    if (isset($fields['Expiry Date'])) {
        $expiryTime = strtotime($fields['Expiry Date']);
        if ($expiryTime) {
            $daysLeft = (int)ceil(($expiryTime - time()) / 86400);
            $fields['Expires In'] = $daysLeft . ' days';
        }
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
            CURLOPT_USERAGENT      => 'mwWhoisLookup/1.0',
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        ]);
        $response = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $code >= 400) {
            return null;
        }
    } else {
        $ctx = stream_context_create([
            'http' => [
                'header' => "Accept: application/rdap+json\r\n",
                'timeout' => 5,
                'follow_location' => 1,
                'max_redirects' => 5,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $response = @file_get_contents($url, false, $ctx);

        if ($response === false) {
            return null;
        }
    }

    $data = json_decode($response, true);

    if (!$data) {
        return null;
    }

    if (isset($data['errorCode'])) {
        return null;
    }

    return $data;
}

function formatRdapResponse(array $rdap): string {
    $lines = [];

    if (isset($rdap['ldhName'])) {
        $lines[] = "Domain Name: " . strtoupper($rdap['ldhName']);
    }

    if (isset($rdap['status']) && is_array($rdap['status'])) {
        foreach ($rdap['status'] as $s) {
            $lines[] = "Domain Status: " . $s;
        }
    }

    if (isset($rdap['events']) && is_array($rdap['events'])) {
        foreach ($rdap['events'] as $e) {
            $action = '';
            if (isset($e['eventAction'])) {
                $action = ucfirst($e['eventAction']);
            }

            $date = '';
            if (isset($e['eventDate'])) {
                $date = $e['eventDate'];
            }

            $lines[] = $action . ": " . $date;
        }
    }

    if (isset($rdap['entities']) && is_array($rdap['entities'])) {
        foreach ($rdap['entities'] as $entity) {
            $roles = '';
            if (isset($entity['roles'])) {
                $roles = implode(', ', $entity['roles']);
            }

            $handle = '';
            if (isset($entity['handle'])) {
                $handle = $entity['handle'];
            }

            if ($roles) {
                $lines[] = ucfirst($roles) . ": " . $handle;
            }

            if (isset($entity['vcardArray'][1]) && is_array($entity['vcardArray'][1])) {
                foreach ($entity['vcardArray'][1] as $vc) {
                    if ($vc[0] === 'fn') {
                        $lines[] = "  Name: " . $vc[3];
                    }
                    if ($vc[0] === 'org') {
                        if (is_array($vc[3])) {
                            $lines[] = "  Organization: " . $vc[3][0];
                        } else {
                            $lines[] = "  Organization: " . $vc[3];
                        }
                    }
                }
            }
        }
    }

    if (isset($rdap['nameservers']) && is_array($rdap['nameservers'])) {
        foreach ($rdap['nameservers'] as $ns) {
            $nsName = '';
            if (isset($ns['ldhName'])) {
                $nsName = $ns['ldhName'];
            }
            $lines[] = "Name Server: " . $nsName;
        }
    }

    return implode("\n", $lines);
}


// ═══════════════════════════════════════════════════════════════════
//  JSON response helper
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
//  Registrar reputation (Issue #51)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check if a registrar is flagged as problematic/spam-friendly.
 *
 * Returns null if unknown, or an associative array with reputation info.
 *
 * @param  string $registrar  The registrar name from WHOIS data
 * @return array|null          ['rating' => 'caution'|'warning', 'reason' => string]
 */
function checkRegistrarReputation(string $registrar): ?array {
    // Normalise for matching
    $lower = strtolower(trim($registrar));

    // Known problematic registrars (curated list)
    $flagged = [
        'todaynic.com'       => ['rating' => 'caution', 'reason' => 'Associated with high volumes of spam and abuse domains'],
        'regru-ru'           => ['rating' => 'caution', 'reason' => 'Frequently used for abuse domains in some reports'],
        'west263'            => ['rating' => 'caution', 'reason' => 'Associated with high abuse rates'],
        'bizcn.com'          => ['rating' => 'caution', 'reason' => 'Known for high abuse domain registration volumes'],
        'ename'              => ['rating' => 'caution', 'reason' => 'Elevated abuse domain rates reported'],
        'xinnet'             => ['rating' => 'caution', 'reason' => 'Elevated abuse domain rates reported'],
        'jiangsu bangning'   => ['rating' => 'caution', 'reason' => 'Elevated abuse domain rates reported'],
        'hichina'            => ['rating' => 'caution', 'reason' => 'Higher-than-average abuse rates reported'],
        'web commerce'       => ['rating' => 'caution', 'reason' => 'Associated with fraudulent domain registrations'],
        'nicenic'            => ['rating' => 'caution', 'reason' => 'Frequently used for phishing domains'],
    ];

    foreach ($flagged as $pattern => $info) {
        if (str_contains($lower, $pattern) ) {
            return $info;
        }
    }

    return null;
}

// ═══════════════════════════════════════════════════════════════════
//  Google Safe Browsing check (Issue #52)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check a domain against the Google Safe Browsing API.
 *
 * @param  string $domain  The domain to check
 * @param  string $apiKey  Google Safe Browsing API key
 * @return array           ['safe' => bool, 'threats' => array]
 */
function checkSafeBrowsing(string $domain, string $apiKey): array {
    $url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey);
    $payload = json_encode([
        'client' => ['clientId' => 'mwwhois', 'clientVersion' => '1.0'],
        'threatInfo' => [
            'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => [
                ['url' => 'http://' . $domain . '/'],
                ['url' => 'https://' . $domain . '/'],
            ],
        ],
    ]);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $payload,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_TIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) {
        return ['safe' => true, 'threats' => [], 'error' => 'API unavailable'];
    }

    $data = json_decode($response, true);
    if (!empty($data['matches'])) {
        $threats = array_map(function ($m) {
            return $m['threatType'];
        }, $data['matches']);
        return ['safe' => false, 'threats' => array_unique($threats)];
    }

    return ['safe' => true, 'threats' => []];
}


// ═══════════════════════════════════════════════════════════════════
//  VirusTotal domain reputation (Issue #53)
// ═══════════════════════════════════════════════════════════════════

/**
 * Query VirusTotal for domain reputation.
 *
 * @param  string $domain  The domain to check
 * @param  string $apiKey  VirusTotal API key
 * @return array|null      Reputation info or null on failure
 */
function checkVirusTotal(string $domain, string $apiKey): ?array {
    $url = 'https://www.virustotal.com/api/v3/domains/' . urlencode($domain);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => ['x-apikey: ' . $apiKey],
        CURLOPT_TIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) {
        return null;
    }

    $data = json_decode($response, true);
    if (empty($data['data']['attributes']['last_analysis_stats'])) {
        return null;
    }

    $stats = $data['data']['attributes']['last_analysis_stats'];
    return [
        'malicious'   => $stats['malicious'] ?? 0,
        'suspicious'  => $stats['suspicious'] ?? 0,
        'harmless'    => $stats['harmless'] ?? 0,
        'undetected'  => $stats['undetected'] ?? 0,
        'reputation'  => $data['data']['attributes']['reputation'] ?? 0,
        'categories'  => $data['data']['attributes']['categories'] ?? [],
    ];
}


function sendJson(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function sendError(string $message, int $status = 400): void {
    sendJson(['error' => $message], $status);
}


// ═══════════════════════════════════════════════════════════════════
//  Subdomain discovery (Issue #46)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check common subdomains for a domain and return which ones resolve.
 *
 * @param  string $domain  The base domain (e.g. example.com)
 * @return array           Array of ['subdomain' => string, 'ip' => string|null]
 */
function discoverSubdomains(string $domain): array {
    $prefixes = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
        'webmail', 'api', 'cdn', 'dev', 'staging', 'test',
        'admin', 'portal', 'blog', 'shop', 'store', 'app',
        'ns1', 'ns2', 'mx', 'vpn', 'remote', 'ssh',
        'git', 'ci', 'status', 'docs', 'help', 'support',
        'm', 'mobile', 'beta', 'alpha', 'demo', 'sandbox',
        'media', 'static', 'assets', 'img', 'images',
    ];

    $results = [];
    foreach ($prefixes as $prefix) {
        $fqdn = $prefix . '.' . $domain;
        $ip = @gethostbyname($fqdn);
        // gethostbyname returns the hostname unchanged if it doesn't resolve
        if ($ip !== $fqdn) {
            $results[] = [
                'subdomain' => $fqdn,
                'ip' => $ip,
            ];
        }
    }

    return $results;
}


// ═══════════════════════════════════════════════════════════════════
//  Have I Been Pwned — domain breach search (Issue #65)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check a domain for known data breaches via HIBP API.
 *
 * @param  string $domain  The domain to check
 * @param  string $apiKey  HIBP API key
 * @return array|null      Array of breach info or null on failure
 */
function checkHibpDomain(string $domain, string $apiKey): ?array {
    $url = 'https://haveibeenpwned.com/api/v3/breaches?domain=' . urlencode($domain);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'hibp-api-key: ' . $apiKey,
            'User-Agent: mwWhoIs-DomainLookup',
        ],
        CURLOPT_TIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 404) {
        return []; // No breaches found
    }

    if ($httpCode !== 200 || !$response) {
        return null; // API error
    }

    $breaches = json_decode($response, true);
    if (!is_array($breaches)) {
        return null;
    }

    return array_map(function ($b) {
        return [
            'name'        => $b['Name'] ?? '',
            'title'       => $b['Title'] ?? '',
            'date'        => $b['BreachDate'] ?? '',
            'pwn_count'   => $b['PwnCount'] ?? 0,
            'data_classes' => $b['DataClasses'] ?? [],
        ];
    }, $breaches);
}


// ═══════════════════════════════════════════════════════════════════
//  DNSSEC validation check (Issue #93)
// ═══════════════════════════════════════════════════════════════════

function checkDnssec(string $domain): array {
    $result = ['signed' => false, 'ds_records' => 0, 'status' => 'unsigned'];

    // Check for DS records (Delegation Signer) which indicate DNSSEC
    $ds = @dns_get_record($domain, DNS_ANY);
    if ($ds) {
        foreach ($ds as $rec) {
            if (isset($rec['type']) && strtoupper($rec['type']) === 'DS') {
                $result['signed'] = true;
                $result['ds_records']++;
            }
        }
    }

    // Also try DNSKEY query
    if (!$result['signed']) {
        $dnskey = @dns_get_record($domain, DNS_ANY);
        if ($dnskey) {
            foreach ($dnskey as $rec) {
                if (isset($rec['type']) && strtoupper($rec['type']) === 'DNSKEY') {
                    $result['signed'] = true;
                    break;
                }
            }
        }
    }

    // Fallback: use dig if available
    if (!$result['signed']) {
        $digOutput = @shell_exec('dig +short DS ' . escapeshellarg($domain) . ' 2>/dev/null');
        if ($digOutput && trim($digOutput)) {
            $result['signed'] = true;
            $result['ds_records'] = count(array_filter(explode("\n", trim($digOutput))));
        }
    }

    $result['status'] = $result['signed'] ? 'signed' : 'unsigned';
    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Certificate Transparency log lookup (Issue #94)
// ═══════════════════════════════════════════════════════════════════

function checkCertTransparency(string $domain): ?array {
    $url = 'https://crt.sh/?q=' . urlencode($domain) . '&output=json&deduplicate=Y';

    $ctx = stream_context_create(['http' => ['timeout' => 5, 'header' => "User-Agent: mwWhoIs\r\n"]]);
    $response = @file_get_contents($url, false, $ctx);
    if (!$response) {
        return null;
    }

    $certs = json_decode($response, true);
    if (!is_array($certs)) {
        return null;
    }

    // Get the 10 most recent
    usort($certs, function ($a, $b) {
        return strtotime($b['entry_timestamp'] ?? '0') - strtotime($a['entry_timestamp'] ?? '0');
    });

    $recent = array_slice($certs, 0, 10);
    return [
        'total' => count($certs),
        'recent' => array_map(function ($c) {
            return [
                'issuer'    => $c['issuer_name'] ?? '',
                'not_before' => $c['not_before'] ?? '',
                'not_after'  => $c['not_after'] ?? '',
                'common_name' => $c['common_name'] ?? '',
            ];
        }, $recent),
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  Domain age risk scoring (Issue #95)
// ═══════════════════════════════════════════════════════════════════

function assessDomainAgeRisk(array $parsed): ?array {
    if (empty($parsed['Creation Date'])) {
        return null;
    }

    try {
        $created = new DateTime($parsed['Creation Date']);
        $now = new DateTime();
        $diff = $now->diff($created);
        $days = (int)$diff->format('%a');

        $risk = 'low';
        $reason = 'Domain is well established';
        if ($days < 30) {
            $risk = 'high';
            $reason = 'Domain registered less than 30 days ago — newly registered domains are frequently used for phishing and spam';
        } elseif ($days < 90) {
            $risk = 'medium';
            $reason = 'Domain registered less than 90 days ago';
        } elseif ($days < 365) {
            $risk = 'low-medium';
            $reason = 'Domain is less than 1 year old';
        }

        return ['risk' => $risk, 'days_old' => $days, 'reason' => $reason];
    } catch (Exception $e) {
        return null;
    }
}


// ═══════════════════════════════════════════════════════════════════
//  AbuseIPDB integration (Issue #96)
// ═══════════════════════════════════════════════════════════════════

function checkAbuseIPDB(string $ip, string $apiKey): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => 'https://api.abuseipdb.com/api/v2/check?' . http_build_query(['ipAddress' => $ip, 'maxAgeInDays' => 90]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_HTTPHEADER => ['Key: ' . $apiKey, 'Accept: application/json'],
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$response) {
        return null;
    }

    $data = json_decode($response, true);
    if (!isset($data['data'])) {
        return null;
    }

    $d = $data['data'];
    return [
        'abuse_score'    => $d['abuseConfidenceScore'] ?? 0,
        'total_reports'  => $d['totalReports'] ?? 0,
        'country_code'   => $d['countryCode'] ?? '',
        'isp'            => $d['isp'] ?? '',
        'is_tor'         => $d['isTor'] ?? false,
        'last_reported'  => $d['lastReportedAt'] ?? null,
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  Shodan integration (Issue #97)
// ═══════════════════════════════════════════════════════════════════

function checkShodan(string $ip, string $apiKey): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $url = 'https://api.shodan.io/shodan/host/' . urlencode($ip) . '?key=' . urlencode($apiKey) . '&minify=true';
    $ctx = stream_context_create(['http' => ['timeout' => 5]]);
    $response = @file_get_contents($url, false, $ctx);
    if (!$response) {
        return null;
    }

    $data = json_decode($response, true);
    if (!is_array($data) || isset($data['error'])) {
        return null;
    }

    $ports = $data['ports'] ?? [];
    sort($ports);

    return [
        'ports'       => $ports,
        'os'          => $data['os'] ?? null,
        'org'         => $data['org'] ?? '',
        'vulns'       => array_keys($data['vulns'] ?? []),
        'last_update' => $data['last_update'] ?? '',
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  PhishTank integration (Issue #98)
// ═══════════════════════════════════════════════════════════════════

function checkPhishTank(string $domain, string $apiKey): ?array {
    $url = 'https://checkurl.phishtank.com/checkurl/';
    $postData = http_build_query([
        'url' => 'https://' . $domain,
        'format' => 'json',
        'app_key' => $apiKey,
    ]);

    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $postData,
            'timeout' => 5,
        ],
    ]);
    $response = @file_get_contents($url, false, $ctx);
    if (!$response) {
        return null;
    }

    $data = json_decode($response, true);
    if (!isset($data['results'])) {
        return null;
    }

    return [
        'in_database' => (bool)($data['results']['in_database'] ?? false),
        'is_phish'    => (bool)($data['results']['valid'] ?? false),
        'verified'    => (bool)($data['results']['verified'] ?? false),
        'phish_id'    => $data['results']['phish_id'] ?? null,
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  URLhaus malware check (Issue #99)
// ═══════════════════════════════════════════════════════════════════

function checkUrlhaus(string $domain): ?array {
    $url = 'https://urlhaus-api.abuse.ch/v1/host/';
    $postData = http_build_query(['host' => $domain]);

    $ctx = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/x-www-form-urlencoded\r\n",
            'content' => $postData,
            'timeout' => 5,
        ],
    ]);
    $response = @file_get_contents($url, false, $ctx);
    if (!$response) {
        return null;
    }

    $data = json_decode($response, true);
    if (!is_array($data)) {
        return null;
    }

    return [
        'status'       => $data['query_status'] ?? 'unknown',
        'urls_total'   => (int)($data['urls_online'] ?? 0),
        'blacklists'   => $data['blacklists'] ?? [],
        'tags'         => array_slice($data['tags'] ?? [], 0, 10),
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  Spamhaus blocklist check (Issue #100)
// ═══════════════════════════════════════════════════════════════════

function checkSpamhaus(string $ip): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return null;
    }

    // Reverse IP for DNSBL query
    $reversed = implode('.', array_reverse(explode('.', $ip)));
    $zones = [
        'zen.spamhaus.org' => 'Spamhaus ZEN (combined)',
        'sbl.spamhaus.org' => 'SBL (Spam)',
        'xbl.spamhaus.org' => 'XBL (Exploits)',
        'pbl.spamhaus.org' => 'PBL (Policy)',
    ];

    $listed = [];
    foreach ($zones as $zone => $label) {
        $lookup = $reversed . '.' . $zone;
        $result = @dns_get_record($lookup, DNS_A);
        if ($result && count($result) > 0) {
            $listed[] = ['zone' => $zone, 'label' => $label, 'response' => $result[0]['ip'] ?? ''];
        }
    }

    return [
        'listed' => count($listed) > 0,
        'lists'  => $listed,
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  MTA-STS check (Issue #101)
// ═══════════════════════════════════════════════════════════════════

function checkMtaSts(string $domain): array {
    $result = ['found' => false, 'record' => null, 'mode' => null];

    // Check _mta-sts TXT record
    $records = @dns_get_record('_mta-sts.' . $domain, DNS_TXT);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=STSv1') !== false) {
                $result['found'] = true;
                $result['record'] = $rec['txt'];

                if (stripos($rec['txt'], 'enforce') !== false) {
                    $result['mode'] = 'enforce';
                } elseif (stripos($rec['txt'], 'testing') !== false) {
                    $result['mode'] = 'testing';
                } elseif (stripos($rec['txt'], 'none') !== false) {
                    $result['mode'] = 'none';
                }
                break;
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  BIMI record check (Issue #102)
// ═══════════════════════════════════════════════════════════════════

function checkBimi(string $domain): array {
    $result = ['found' => false, 'record' => null, 'logo_url' => null];

    $records = @dns_get_record('default._bimi.' . $domain, DNS_TXT);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=BIMI1') !== false) {
                $result['found'] = true;
                $result['record'] = $rec['txt'];

                // Extract logo URL
                if (preg_match('/l=([^;\s]+)/i', $rec['txt'], $m)) {
                    $result['logo_url'] = trim($m[1]);
                }
                break;
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  DANE/TLSA record check (Issue #103)
// ═══════════════════════════════════════════════════════════════════

function checkDaneTlsa(string $domain): array {
    $result = ['found' => false, 'records' => []];

    // Check _443._tcp.{domain} for TLSA records
    $host = '_443._tcp.' . $domain;

    // PHP dns_get_record doesn't support TLSA natively, use dig
    $output = @shell_exec('dig +short TLSA ' . escapeshellarg($host) . ' 2>/dev/null');
    if ($output && trim($output)) {
        $lines = array_filter(explode("\n", trim($output)));
        $result['found'] = true;
        foreach ($lines as $line) {
            $parts = preg_split('/\s+/', trim($line), 4);
            if (count($parts) >= 4) {
                $result['records'][] = [
                    'usage'    => (int)$parts[0],
                    'selector' => (int)$parts[1],
                    'matching' => (int)$parts[2],
                    'data'     => substr($parts[3], 0, 32) . '...',
                ];
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  WHOIS privacy detection (Issue #104)
// ═══════════════════════════════════════════════════════════════════

function detectWhoisPrivacy(string $whoisText, array $parsed): array {
    $result = ['privacy_enabled' => false, 'indicators' => []];

    $privacyKeywords = [
        'REDACTED FOR PRIVACY',
        'Privacy Protection',
        'WhoisGuard',
        'Domains By Proxy',
        'Contact Privacy',
        'WHOIS PRIVACY',
        'Identity Protection',
        'Privacy Service',
        'Data Protected',
        'Withheld for Privacy',
        'Statutory Masking',
        'GDPR Redacted',
        'Not Disclosed',
        'Registration Private',
    ];

    foreach ($privacyKeywords as $keyword) {
        if (stripos($whoisText, $keyword) !== false) {
            $result['privacy_enabled'] = true;
            $result['indicators'][] = $keyword;
        }
    }

    // Check if registrant org looks like a privacy service
    $org = $parsed['Registrant Org'] ?? ($parsed['Organisation'] ?? '');
    $privacyOrgs = ['proxy', 'privacy', 'protect', 'guard', 'redacted', 'withheld'];
    foreach ($privacyOrgs as $term) {
        if ($org && stripos($org, $term) !== false) {
            $result['privacy_enabled'] = true;
            if (!in_array($org, $result['indicators'])) {
                $result['indicators'][] = 'Registrant: ' . $org;
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Hosting country risk assessment (Issue #105)
// ═══════════════════════════════════════════════════════════════════

function assessHostingRisk(?array $geolocation): ?array {
    if (!$geolocation || empty($geolocation['country_code'])) {
        return null;
    }

    // Countries frequently flagged in threat intelligence reports
    $highRisk = ['RU', 'CN', 'KP', 'IR', 'SY', 'CU'];
    $mediumRisk = ['UA', 'RO', 'BG', 'NG', 'PK', 'BD', 'VN', 'BY'];

    $cc = strtoupper($geolocation['country_code']);
    $country = $geolocation['country'] ?? $cc;

    if (in_array($cc, $highRisk)) {
        return ['risk' => 'high', 'country' => $country, 'country_code' => $cc, 'reason' => 'Hosted in a jurisdiction frequently associated with cyber threats'];
    }
    if (in_array($cc, $mediumRisk)) {
        return ['risk' => 'medium', 'country' => $country, 'country_code' => $cc, 'reason' => 'Hosted in a jurisdiction with elevated cyber threat activity'];
    }

    return ['risk' => 'low', 'country' => $country, 'country_code' => $cc, 'reason' => ''];
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP Security Headers audit (Issue #106)
// ═══════════════════════════════════════════════════════════════════

function auditHttpHeaders(string $domain): ?array {
    $url = 'https://' . $domain;
    $ctx = stream_context_create(['http' => ['method' => 'HEAD', 'timeout' => 5, 'follow_location' => 1, 'max_redirects' => 3, 'header' => "User-Agent: mwWhoIs Security Audit\r\n"], 'ssl' => ['verify_peer' => false]]);
    $headers = @get_headers($url, true, $ctx);
    if (!$headers) {
        // Try HTTP fallback
        $url = 'http://' . $domain;
        $headers = @get_headers($url, true, $ctx);
        if (!$headers) {
            return null;
        }
    }

    // Normalise header keys to lowercase
    $h = [];
    foreach ($headers as $k => $v) {
        if (is_string($k)) {
            $h[strtolower($k)] = is_array($v) ? end($v) : $v;
        }
    }

    $checks = [
        'strict-transport-security' => ['label' => 'HSTS', 'desc' => 'Enforces HTTPS connections'],
        'content-security-policy'   => ['label' => 'CSP', 'desc' => 'Controls resource loading sources'],
        'x-frame-options'           => ['label' => 'X-Frame-Options', 'desc' => 'Prevents clickjacking'],
        'x-content-type-options'    => ['label' => 'X-Content-Type-Options', 'desc' => 'Prevents MIME sniffing'],
        'referrer-policy'           => ['label' => 'Referrer-Policy', 'desc' => 'Controls referrer information'],
        'permissions-policy'        => ['label' => 'Permissions-Policy', 'desc' => 'Controls browser features'],
        'cross-origin-opener-policy' => ['label' => 'COOP', 'desc' => 'Cross-origin opener policy'],
        'cross-origin-resource-policy' => ['label' => 'CORP', 'desc' => 'Cross-origin resource policy'],
    ];

    $results = [];
    $pass = 0;
    $total = count($checks);
    foreach ($checks as $header => $meta) {
        $present = isset($h[$header]);
        $value = $present ? $h[$header] : null;
        $results[] = ['header' => $meta['label'], 'description' => $meta['desc'], 'present' => $present, 'value' => $value];
        if ($present) {
            $pass++;
        }
    }

    $grade = 'F';
    $pct = ($pass / $total) * 100;
    if ($pct >= 87) {
        $grade = 'A';
    } elseif ($pct >= 75) {
        $grade = 'B';
    } elseif ($pct >= 62) {
        $grade = 'C';
    } elseif ($pct >= 50) {
        $grade = 'D';
    } elseif ($pct >= 37) {
        $grade = 'E';
    }

    return ['grade' => $grade, 'pass' => $pass, 'total' => $total, 'headers' => $results];
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP Redirect chain detection (Issue #107)
// ═══════════════════════════════════════════════════════════════════

function detectRedirectChain(string $domain): ?array {
    $chain = [];
    $url = 'http://' . $domain;
    $maxRedirects = 10;

    for ($i = 0; $i < $maxRedirects; $i++) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'mwWhoIs',
        ]);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        curl_close($ch);

        $chain[] = ['url' => $url, 'status' => $httpCode];

        if ($httpCode >= 300 && $httpCode < 400 && $redirectUrl) {
            $url = $redirectUrl;
        } else {
            break;
        }
    }

    $suspicious = count($chain) > 5;
    $httpToHttps = false;
    if (count($chain) >= 2 && str_starts_with($chain[0]['url'], 'http://') && str_starts_with(end($chain)['url'], 'https://')) {
        $httpToHttps = true;
    }

    return ['chain' => $chain, 'hops' => count($chain), 'http_to_https' => $httpToHttps, 'suspicious' => $suspicious];
}


// ═══════════════════════════════════════════════════════════════════
//  TLS version & cipher suite audit (Issue #108)
// ═══════════════════════════════════════════════════════════════════

function auditTlsVersions(string $domain): ?array {
    $result = ['versions' => [], 'cipher' => null, 'protocol' => null, 'insecure' => false];

    // Check negotiated TLS version
    $ch = curl_init('https://' . $domain);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 5, CURLOPT_SSL_VERIFYPEER => false]);
    curl_exec($ch);
    $sslVersion = curl_getinfo($ch, CURLINFO_SSL_VERIFYRESULT);
    $protocol = curl_getinfo($ch, CURLINFO_PROTOCOL);

    // Get TLS version from verbose info
    $tlsVer = null;
    if (defined('CURLINFO_TLS_SSL_PTR')) {
        // Not available in all PHP versions
    }

    // Fallback: use openssl s_client
    $output = @shell_exec('echo | timeout 5 openssl s_client -connect ' . escapeshellarg($domain . ':443') . ' 2>/dev/null | grep "Protocol\|Cipher"');
    if ($output) {
        if (preg_match('/Protocol\s*:\s*(.+)/i', $output, $m)) {
            $result['protocol'] = trim($m[1]);
        }
        if (preg_match('/Cipher\s*:\s*(.+)/i', $output, $m)) {
            $result['cipher'] = trim($m[1]);
        }
    }
    curl_close($ch);

    // Test specific TLS versions
    $tests = [
        'TLSv1.0' => CURL_SSLVERSION_TLSv1_0,
        'TLSv1.1' => CURL_SSLVERSION_TLSv1_1,
        'TLSv1.2' => CURL_SSLVERSION_TLSv1_2,
    ];
    if (defined('CURL_SSLVERSION_TLSv1_3')) {
        $tests['TLSv1.3'] = CURL_SSLVERSION_TLSv1_3;
    }

    foreach ($tests as $name => $const) {
        $ch = curl_init('https://' . $domain);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 3, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSLVERSION => $const]);
        $ok = curl_exec($ch);
        $err = curl_errno($ch);
        curl_close($ch);
        $supported = ($err === 0);
        $result['versions'][$name] = $supported;
        if ($supported && ($name === 'TLSv1.0' || $name === 'TLSv1.1')) {
            $result['insecure'] = true;
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  CAA record check (Issue #109)
// ═══════════════════════════════════════════════════════════════════

function checkCaaRecords(string $domain): array {
    $result = ['found' => false, 'records' => []];

    // PHP dns_get_record supports CAA natively (PHP 8.4+)
    $records = @dns_get_record($domain, DNS_CAA);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['type']) && $rec['type'] === 'CAA') {
                $result['found'] = true;
                $result['records'][] = [
                    'flag'  => $rec['flags'] ?? 0,
                    'tag'   => $rec['tag'] ?? '',
                    'value' => $rec['value'] ?? '',
                ];
            }
        }
    }

    // Fallback via dig
    if (!$result['found']) {
        $output = @shell_exec('dig +short CAA ' . escapeshellarg($domain) . ' 2>/dev/null');
        if ($output && trim($output)) {
            $lines = array_filter(explode("\n", trim($output)));
            foreach ($lines as $line) {
                $parts = preg_split('/\s+/', trim($line), 3);
                if (count($parts) >= 3) {
                    $result['found'] = true;
                    $result['records'][] = ['flag' => (int)$parts[0], 'tag' => $parts[1], 'value' => trim($parts[2], '"')];
                }
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  SMTP banner & STARTTLS check (Issue #110)
// ═══════════════════════════════════════════════════════════════════

function checkSmtpSecurity(string $domain): ?array {
    // Get MX records
    $mxRecords = @dns_get_record($domain, DNS_MX);
    if (!$mxRecords || count($mxRecords) === 0) {
        return null;
    }

    // Sort by priority and use the first
    usort($mxRecords, function ($a, $b) {
        return ($a['pri'] ?? 99) - ($b['pri'] ?? 99);
    });
    $mxHost = $mxRecords[0]['target'] ?? null;
    if (!$mxHost) {
        return null;
    }

    $result = ['mx_host' => $mxHost, 'banner' => null, 'starttls' => false, 'reachable' => false];

    $fp = @fsockopen($mxHost, 25, $errno, $errstr, 5);
    if (!$fp) {
        return $result;
    }

    $result['reachable'] = true;
    stream_set_timeout($fp, 5);

    // Read banner
    $banner = fgets($fp, 1024);
    $result['banner'] = trim($banner);

    // Send EHLO
    fwrite($fp, "EHLO mwwhois.check\r\n");
    $ehloResponse = '';
    while ($line = fgets($fp, 1024)) {
        $ehloResponse .= $line;
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }

    $result['starttls'] = (stripos($ehloResponse, 'STARTTLS') !== false);

    fwrite($fp, "QUIT\r\n");
    fclose($fp);

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Reverse IP lookup (Issue #111)
// ═══════════════════════════════════════════════════════════════════

function reverseIpLookup(string $ip): ?array {
    $url = 'https://api.hackertarget.com/reverseiplookup/?q=' . urlencode($ip);
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'header' => "User-Agent: mwWhoIs\r\n"]]);
    $response = @file_get_contents($url, false, $ctx);
    if (!$response || str_contains($response, 'error')  || str_contains($response, 'API count') ) {
        return null;
    }

    $domains = array_filter(array_map('trim', explode("\n", trim($response))));
    return ['ip' => $ip, 'count' => count($domains), 'domains' => array_slice($domains, 0, 25)];
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP/2 and HTTP/3 support detection (Issue #112)
// ═══════════════════════════════════════════════════════════════════

function checkHttpVersions(string $domain): array {
    $result = ['http2' => false, 'http3' => false, 'protocol' => null];

    $ch = curl_init('https://' . $domain);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0,
        CURLOPT_HEADER => true,
    ]);
    $response = curl_exec($ch);
    $httpVersion = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
    curl_close($ch);

    if ($httpVersion === CURL_HTTP_VERSION_2_0 || $httpVersion === 2) {
        $result['http2'] = true;
        $result['protocol'] = 'HTTP/2';
    } elseif ($httpVersion === CURL_HTTP_VERSION_1_1 || $httpVersion === 1) {
        $result['protocol'] = 'HTTP/1.1';
    }

    // Check for HTTP/3 via Alt-Svc header
    if ($response && preg_match('/alt-svc:\s*([^\r\n]+)/i', $response, $m)) {
        if (stripos($m[1], 'h3') !== false) {
            $result['http3'] = true;
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  IPv6 readiness check (Issue #113)
// ═══════════════════════════════════════════════════════════════════

function checkIpv6Readiness(string $domain): array {
    $result = ['has_aaaa' => false, 'aaaa_records' => [], 'reachable' => null];

    $records = @dns_get_record($domain, DNS_AAAA);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['ipv6'])) {
                $result['has_aaaa'] = true;
                $result['aaaa_records'][] = $rec['ipv6'];
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  DNS resolution & HTTP response time (Issue #114)
// ═══════════════════════════════════════════════════════════════════

function measureResponseTimes(string $domain): array {
    $result = ['dns_ms' => null, 'ttfb_ms' => null, 'total_ms' => null];

    $ch = curl_init('https://' . $domain);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'mwWhoIs',
    ]);
    curl_exec($ch);

    if (curl_errno($ch) === 0) {
        $result['dns_ms'] = round(curl_getinfo($ch, CURLINFO_NAMELOOKUP_TIME) * 1000);
        $result['ttfb_ms'] = round(curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME) * 1000);
        $result['total_ms'] = round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
    }
    curl_close($ch);

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Nameserver diversity check (Issue #115)
// ═══════════════════════════════════════════════════════════════════

function checkNsDiversity(string $domain): array {
    $result = ['nameservers' => [], 'unique_networks' => 0, 'diverse' => true, 'warning' => null];

    $nsRecords = @dns_get_record($domain, DNS_NS);
    if (!$nsRecords) {
        return $result;
    }

    $networks = [];
    foreach ($nsRecords as $rec) {
        $ns = $rec['target'] ?? '';
        if (!$ns) {
            continue;
        }

        $nsIp = @gethostbyname($ns);
        $network = ($nsIp !== $ns) ? implode('.', array_slice(explode('.', $nsIp), 0, 2)) . '.x.x' : 'unknown';
        $result['nameservers'][] = ['hostname' => $ns, 'ip' => ($nsIp !== $ns) ? $nsIp : null, 'network' => $network];
        $networks[$network] = true;
    }

    $result['unique_networks'] = count($networks);
    if (count($result['nameservers']) > 1 && $result['unique_networks'] <= 1) {
        $result['diverse'] = false;
        $result['warning'] = 'All nameservers are in the same network — single point of failure risk';
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Domain name suggestions (Issue #116)
// ═══════════════════════════════════════════════════════════════════

function suggestAlternativeDomains(string $domain): array {
    $parts = explode('.', $domain, 2);
    $name = $parts[0];
    $currentTld = $parts[1] ?? 'com';

    $altTlds = ['com', 'net', 'org', 'io', 'co', 'info', 'biz', 'dev', 'app', 'xyz', 'me', 'co.uk', 'uk'];
    $suggestions = [];

    foreach ($altTlds as $tld) {
        if ($tld === $currentTld) {
            continue;
        }
        $candidate = $name . '.' . $tld;
        $whois = @shell_exec('whois ' . escapeshellarg($candidate) . ' 2>&1');
        if ($whois) {
            $avail = detectAvailability($whois);
            if ($avail === 'available') {
                $suggestions[] = $candidate;
            }
        }
        if (count($suggestions) >= 5) {
            break; // Limit to 5 suggestions
        }
    }

    return $suggestions;
}


// ═══════════════════════════════════════════════════════════════════
//  Technology stack detection (Issue #124)
// ═══════════════════════════════════════════════════════════════════

function detectTechStack(string $domain): ?array {
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'method' => 'GET', 'header' => "User-Agent: mwWhoIs\r\n", 'follow_location' => 1, 'max_redirects' => 3], 'ssl' => ['verify_peer' => false]]);
    $html = @file_get_contents('https://' . $domain, false, $ctx);
    $headers = [];
    if (isset($http_response_header)) {
        foreach ($http_response_header as $h) {
            $parts = explode(':', $h, 2);
            if (count($parts) === 2) {
                $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }
    }

    $techs = [];

    // Server
    if (!empty($headers['server'])) {
        $techs[] = ['category' => 'Server', 'name' => $headers['server']];
    }
    if (!empty($headers['x-powered-by'])) {
        $techs[] = ['category' => 'Framework', 'name' => $headers['x-powered-by']];
    }

    if ($html) {
        // CMS detection
        if (str_contains(strtolower($html), 'wp-content')  || str_contains(strtolower($html), 'wordpress') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'WordPress'];
        } elseif (str_contains(strtolower($html), 'joomla') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Joomla'];
        } elseif (str_contains(strtolower($html), 'drupal') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Drupal'];
        } elseif (str_contains(strtolower($html), 'shopify') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Shopify'];
        } elseif (str_contains(strtolower($html), 'squarespace') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Squarespace'];
        } elseif (str_contains(strtolower($html), 'wix.com') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Wix'];
        }

        // JS frameworks
        if (str_contains(strtolower($html), 'react')  || str_contains(strtolower($html), '__next_data__') ) {
            $techs[] = ['category' => 'JS Framework', 'name' => 'React'];
        }
        if (str_contains(strtolower($html), 'vue')  && str_contains(strtolower($html), 'data-v-') ) {
            $techs[] = ['category' => 'JS Framework', 'name' => 'Vue.js'];
        }
        if (str_contains(strtolower($html), 'angular')  || str_contains(strtolower($html), 'ng-') ) {
            $techs[] = ['category' => 'JS Framework', 'name' => 'Angular'];
        }

        // CDN
        if (str_contains(strtolower($html), 'cloudflare')  || !empty($headers['cf-ray'])) {
            $techs[] = ['category' => 'CDN', 'name' => 'Cloudflare'];
        }
        if (str_contains(strtolower($html), 'cdn.jsdelivr.net') ) {
            $techs[] = ['category' => 'CDN', 'name' => 'jsDelivr'];
        }
        if (str_contains(strtolower($html), 'cloudfront') ) {
            $techs[] = ['category' => 'CDN', 'name' => 'CloudFront'];
        }
        if (str_contains(strtolower($html), 'akamai') ) {
            $techs[] = ['category' => 'CDN', 'name' => 'Akamai'];
        }

        // Analytics
        if (str_contains(strtolower($html), 'google-analytics')  || str_contains(strtolower($html), 'gtag')  || str_contains(strtolower($html), 'ga-') ) {
            $techs[] = ['category' => 'Analytics', 'name' => 'Google Analytics'];
        }
        if (str_contains(strtolower($html), 'matomo')  || str_contains(strtolower($html), 'piwik') ) {
            $techs[] = ['category' => 'Analytics', 'name' => 'Matomo'];
        }

        // Meta generator
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) {
            $techs[] = ['category' => 'Generator', 'name' => $m[1]];
        }
    }

    return count($techs) > 0 ? $techs : null;
}


// ═══════════════════════════════════════════════════════════════════
//  Robots.txt & sitemap.xml analysis (Issue #125)
// ═══════════════════════════════════════════════════════════════════

function analyseRobotsTxt(string $domain): ?array {
    $result = ['robots_found' => false, 'sitemap_found' => false, 'disallowed' => [], 'sitemaps' => [], 'crawl_delay' => null];
    $ctx = stream_context_create(['http' => ['timeout' => 5, 'header' => "User-Agent: mwWhoIs\r\n"], 'ssl' => ['verify_peer' => false]]);

    $robots = @file_get_contents('https://' . $domain . '/robots.txt', false, $ctx);
    if ($robots && stripos($robots, '<html') === false) {
        $result['robots_found'] = true;
        foreach (explode("\n", $robots) as $line) {
            $line = trim($line);
            if (str_starts_with(strtolower($line), 'disallow:')) {
                $path = trim(substr($line, 9));
                if ($path) {
                    $result['disallowed'][] = $path;
                }
            } elseif (str_starts_with(strtolower($line), 'sitemap:')) {
                $result['sitemaps'][] = trim(substr($line, 8));
            } elseif (str_starts_with(strtolower($line), 'crawl-delay:')) {
                $result['crawl_delay'] = (int)trim(substr($line, 12));
            }
        }
        $result['disallowed'] = array_slice(array_unique($result['disallowed']), 0, 20);
    }

    // Check sitemap.xml
    $sitemapHeaders = @get_headers('https://' . $domain . '/sitemap.xml', true, $ctx);
    if ($sitemapHeaders && isset($sitemapHeaders[0]) && str_contains($sitemapHeaders[0], '200') ) {
        $result['sitemap_found'] = true;
        if (!in_array('https://' . $domain . '/sitemap.xml', $result['sitemaps'])) {
            $result['sitemaps'][] = 'https://' . $domain . '/sitemap.xml';
        }
    }

    return ($result['robots_found'] || $result['sitemap_found']) ? $result : null;
}


// ═══════════════════════════════════════════════════════════════════
//  DNS propagation checker (Issue #126)
// ═══════════════════════════════════════════════════════════════════

function checkDnsPropagation(string $domain): array {
    $resolvers = [
        'Google' => '8.8.8.8',
        'Cloudflare' => '1.1.1.1',
        'OpenDNS' => '208.67.222.222',
        'Quad9' => '9.9.9.9',
    ];

    $results = [];
    foreach ($resolvers as $name => $ip) {
        $output = @shell_exec('dig @' . escapeshellarg($ip) . ' +short A ' . escapeshellarg($domain) . ' 2>/dev/null');
        $ips = $output ? array_filter(array_map('trim', explode("\n", trim($output)))) : [];
        $results[] = ['resolver' => $name, 'ip' => $ip, 'answers' => $ips];
    }

    // Check consistency
    $allAnswers = array_map(function ($r) {
        return implode(',', $r['answers']);
    }, $results);
    $consistent = count(array_unique($allAnswers)) <= 1;

    return ['resolvers' => $results, 'consistent' => $consistent];
}


// ═══════════════════════════════════════════════════════════════════
//  Security score aggregation (Issue #128)
// ═══════════════════════════════════════════════════════════════════

function calculateSecurityScore(array $data): array {
    $details = [];

    // HTTPS (via SSL info)
    $httpsPass = !empty($data['ssl']);
    $details[] = [
        'name' => 'HTTPS / SSL',
        'status' => $httpsPass ? 'pass' : 'fail',
        'info' => $httpsPass ? 'Valid SSL certificate detected' : 'No SSL certificate found',
        'recommendation' => $httpsPass ? null : 'Install an SSL/TLS certificate and enforce HTTPS',
        'guide' => $httpsPass ? null : 'https://letsencrypt.org/getting-started/',
    ];

    // HSTS
    $hstsPass = false;
    if (!empty($data['http_headers'])) {
        foreach ($data['http_headers']['headers'] ?? [] as $h) {
            if ($h['header'] === 'HSTS' && $h['present']) {
                $hstsPass = true;
                break;
            }
        }
    }
    $details[] = [
        'name' => 'HSTS',
        'status' => $hstsPass ? 'pass' : 'fail',
        'info' => $hstsPass ? 'Strict-Transport-Security header present' : 'HSTS header not found',
        'recommendation' => $hstsPass ? null : 'Add a Strict-Transport-Security header to enforce HTTPS connections',
        'guide' => $hstsPass ? null : 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security',
    ];

    // DNSSEC
    $dnssecPass = !empty($data['dnssec']['signed']);
    $details[] = [
        'name' => 'DNSSEC',
        'status' => $dnssecPass ? 'pass' : 'fail',
        'info' => $dnssecPass ? 'DNSSEC signatures verified' : 'DNSSEC not enabled',
        'recommendation' => $dnssecPass ? null : 'Enable DNSSEC with your DNS provider to protect against DNS spoofing',
        'guide' => $dnssecPass ? null : 'https://www.icann.org/resources/pages/dnssec-what-is-it-why-is-it-important-2019-03-05-en',
    ];

    // SPF
    $spfPass = !empty($data['email_security']['spf']['found']);
    $details[] = [
        'name' => 'SPF',
        'status' => $spfPass ? 'pass' : 'fail',
        'info' => $spfPass ? 'SPF record found' : 'No SPF record',
        'recommendation' => $spfPass ? null : 'Add an SPF TXT record to specify authorised mail servers',
        'guide' => $spfPass ? null : 'https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-spf-record/',
    ];

    // DMARC
    $dmarcPass = !empty($data['email_security']['dmarc']['found']);
    $details[] = [
        'name' => 'DMARC',
        'status' => $dmarcPass ? 'pass' : 'fail',
        'info' => $dmarcPass ? 'DMARC policy found' : 'No DMARC policy',
        'recommendation' => $dmarcPass ? null : 'Add a DMARC TXT record to protect against email spoofing',
        'guide' => $dmarcPass ? null : 'https://dmarc.org/overview/',
    ];

    // DKIM
    $dkimPass = !empty($data['email_security']['dkim']['found']);
    $details[] = [
        'name' => 'DKIM',
        'status' => $dkimPass ? 'pass' : 'warn',
        'info' => $dkimPass ? 'DKIM selector found' : 'DKIM not detected (common selectors checked)',
        'recommendation' => $dkimPass ? null : 'Configure DKIM signing with your email provider',
        'guide' => $dkimPass ? null : 'https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-dkim-record/',
    ];

    // MTA-STS
    $mtaStsPass = !empty($data['mta_sts']['found']);
    $details[] = [
        'name' => 'MTA-STS',
        'status' => $mtaStsPass ? 'pass' : 'warn',
        'info' => $mtaStsPass ? 'MTA-STS policy published' : 'No MTA-STS policy',
        'recommendation' => $mtaStsPass ? null : 'Publish an MTA-STS policy to enforce TLS for inbound email',
        'guide' => $mtaStsPass ? null : 'https://www.hardenize.com/blog/mta-sts/',
    ];

    // TLS 1.2+ only (no 1.0/1.1)
    $tlsPass = !empty($data['tls_audit']) && empty($data['tls_audit']['insecure']);
    $details[] = [
        'name' => 'TLS Version',
        'status' => $tlsPass ? 'pass' : 'fail',
        'info' => $tlsPass ? 'Only TLS 1.2+ supported' : 'Insecure TLS versions (1.0/1.1) accepted',
        'recommendation' => $tlsPass ? null : 'Disable TLS 1.0 and 1.1 on your web server',
        'guide' => $tlsPass ? null : 'https://ssl-config.mozilla.org/',
    ];

    // Not on blocklists
    $blPass = empty($data['spamhaus']['listed']);
    $details[] = [
        'name' => 'Blocklist',
        'status' => $blPass ? 'pass' : 'fail',
        'info' => $blPass ? 'Not listed on Spamhaus' : 'Listed on Spamhaus blocklist',
        'recommendation' => $blPass ? null : 'Investigate and resolve the blocklist listing at spamhaus.org',
        'guide' => $blPass ? null : 'https://www.spamhaus.org/blocklists/do-not-block/',
    ];

    // CAA records
    $caaPass = !empty($data['caa_records']['found']);
    $details[] = [
        'name' => 'CAA Records',
        'status' => $caaPass ? 'pass' : 'warn',
        'info' => $caaPass ? 'CAA records restrict certificate issuance' : 'No CAA records found',
        'recommendation' => $caaPass ? null : 'Add CAA DNS records to control which CAs can issue certificates',
        'guide' => $caaPass ? null : 'https://letsencrypt.org/docs/caa/',
    ];

    // No malware/phishing
    $malwarePass = empty($data['urlhaus']['urls_total']) || $data['urlhaus']['urls_total'] === 0;
    $details[] = [
        'name' => 'Malware / Phishing',
        'status' => $malwarePass ? 'pass' : 'fail',
        'info' => $malwarePass ? 'No known malware URLs' : 'Malware URLs associated with this domain',
        'recommendation' => $malwarePass ? null : 'Scan your site for compromised files and remove malicious content',
        'guide' => $malwarePass ? null : 'https://developers.google.com/web/fundamentals/security/hacked/',
    ];

    $passed = 0;
    foreach ($details as $d) {
        if ($d['status'] === 'pass') {
            $passed++;
        }
    }
    $total = count($details);
    $pct = $total > 0 ? round(($passed / $total) * 100) : 0;
    $grade = 'F';
    if ($pct >= 90) {
        $grade = 'A';
    } elseif ($pct >= 75) {
        $grade = 'B';
    } elseif ($pct >= 60) {
        $grade = 'C';
    } elseif ($pct >= 45) {
        $grade = 'D';
    } elseif ($pct >= 30) {
        $grade = 'E';
    }

    return ['grade' => $grade, 'score' => $pct, 'passed' => $passed, 'total' => $total, 'details' => $details];
}


// ═══════════════════════════════════════════════════════════════════
//  Multi-DNSBL check (Issue #133)
// ═══════════════════════════════════════════════════════════════════

function checkMultiDnsbl(string $ip): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return ['listed' => false, 'lists' => []];
    }

    $reversed = implode('.', array_reverse(explode('.', $ip)));
    $zones = [
        'zen.spamhaus.org' => 'Spamhaus ZEN',
        'b.barracudacentral.org' => 'Barracuda',
        'bl.spamcop.net' => 'SpamCop',
        'dnsbl.sorbs.net' => 'SORBS',
        'dnsbl-1.uceprotect.net' => 'UCEPROTECT L1',
        'cbl.abuseat.org' => 'CBL',
        'dyna.spamrats.com' => 'SpamRATS',
        'bl.mailspike.net' => 'Mailspike',
    ];

    $listed = [];
    foreach ($zones as $zone => $label) {
        $result = @dns_get_record($reversed . '.' . $zone, DNS_A);
        if ($result && count($result) > 0) {
            $listed[] = ['zone' => $zone, 'label' => $label];
        }
    }

    return ['ip' => $ip, 'listed' => count($listed) > 0, 'total_checked' => count($zones), 'lists' => $listed];
}
