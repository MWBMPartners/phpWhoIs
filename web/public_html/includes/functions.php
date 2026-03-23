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
    if (!$records) return false;

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
    if (!defined('CACHE_DIR')) return [];
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . 'api_keys.json';
    if (!file_exists($file)) return [];
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
    if (!$keyConfig) return RATE_LIMIT_MAX; // Default: 30/min
    return isset($keyConfig['rate_limit']) ? (int)$keyConfig['rate_limit'] : RATE_LIMIT_MAX;
}


// ═══════════════════════════════════════════════════════════════════
//  Lookup statistics tracking (Issue #60)
// ═══════════════════════════════════════════════════════════════════

function trackLookup(string $type, string $domain = ''): void {
    if (!defined('CACHE_DIR')) return;
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . 'lookup_stats.json';
    $stats = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    if (!$stats) $stats = ['total' => 0, 'cache_hits' => 0, 'rdap' => 0, 'whois' => 0, 'errors' => 0, 'popular_domains' => []];

    $stats['total'] = ($stats['total'] ?? 0) + 1;
    if ($type === 'cache_hit') $stats['cache_hits'] = ($stats['cache_hits'] ?? 0) + 1;
    if ($type === 'rdap') $stats['rdap'] = ($stats['rdap'] ?? 0) + 1;
    if ($type === 'whois') $stats['whois'] = ($stats['whois'] ?? 0) + 1;
    if ($type === 'error') $stats['errors'] = ($stats['errors'] ?? 0) + 1;

    if ($domain) {
        if (!isset($stats['popular_domains'])) $stats['popular_domains'] = [];
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

        if (!$inIcann || $line === '' || strpos($line, '//') === 0) {
            continue;
        }

        // Only keep multi-part entries (contain a dot) — skip wildcard/negation entries
        if (strpos($line, '.') !== false && strpos($line, '*') !== 0 && strpos($line, '!') !== 0) {
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
    return filter_var($input, FILTER_VALIDATE_IP) !== false;
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
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=spf1') === 0) {
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
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=DMARC1') === 0) {
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
        if (strpos($lower, $pattern) !== false) {
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
