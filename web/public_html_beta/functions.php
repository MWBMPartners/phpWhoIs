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
    $logDir = dirname(__FILE__) . DIRECTORY_SEPARATOR . 'logs';
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
    $ip = '';
    if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    } elseif (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    $ip = trim($ip);
    if ($ip === '') {
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
//  Result caching
// ═══════════════════════════════════════════════════════════════════

function getCached(string $domain): ?string {
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

    // Standard domain format validation
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

function sendJson(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function sendError(string $message, int $status = 400): void {
    sendJson(['error' => $message], $status);
}
