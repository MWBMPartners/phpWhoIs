<?php //https://chatgpt.com/share/66ed46d1-c1a4-800b-bc0a-93663c3084dd
session_start();

// Disable browser, server, and intermediary caching to ensure fresh results
header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
header("Cache-Control: post-check=0, pre-check=0", false);
header("Pragma: no-cache");
header("Expires: Thu, 01 Jan 1970 00:00:00 GMT");

// Path to store the public suffix list metadata (e.g., ETag and Last-Modified)
//define('METADATA_FILE', 'suffix_list_metadata.json');
define('METADATA_FILE', dirname(dirname(__FILE__)). DIRECTORY_SEPARATOR .'_libs'. DIRECTORY_SEPARATOR .'suffix_list_metadata.json');
// URL for the Mozilla Public Suffix List
define('PUBLIC_SUFFIX_LIST_URL', 'https://publicsuffix.org/list/public_suffix_list.dat');

// WHOIS result cache directory and TTL (Issue #11)
define('WHOIS_CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');
define('WHOIS_CACHE_TTL', 900); // 15 minutes

// Rate limiting: max lookups per window (Issue #1)
define('RATE_LIMIT_MAX', 30);
define('RATE_LIMIT_WINDOW', 60); // seconds

// CSRF validation (Issue #1)
function validateCsrfToken() {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

// Rate limiting via session (Issue #1)
function checkRateLimit() {
    $now = time();
    if (!isset($_SESSION['rate_limit'])) {
        $_SESSION['rate_limit'] = ['count' => 0, 'window_start' => $now];
    }
    if ($now - $_SESSION['rate_limit']['window_start'] > RATE_LIMIT_WINDOW) {
        $_SESSION['rate_limit'] = ['count' => 0, 'window_start' => $now];
    }
    $_SESSION['rate_limit']['count']++;
    return $_SESSION['rate_limit']['count'] <= RATE_LIMIT_MAX;
}

// WHOIS result caching (Issue #11)
function getCachedWhois($domain) {
    $cacheFile = WHOIS_CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';
    if (file_exists($cacheFile)) {
        $data = json_decode(file_get_contents($cacheFile), true);
        if ($data && (time() - $data['timestamp']) < WHOIS_CACHE_TTL) {
            return $data['result'];
        }
    }
    return null;
}

function setCachedWhois($domain, $result) {
    if (!is_dir(WHOIS_CACHE_DIR)) {
        @mkdir(WHOIS_CACHE_DIR, 0755, true);
    }
    $cacheFile = WHOIS_CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';
    file_put_contents($cacheFile, json_encode(['timestamp' => time(), 'result' => $result]));
}

// Function to update the public suffix list, only if it has changed
// This ensures we always have the latest list but avoid unnecessary downloads
function updatePublicSuffixList() {
    $headers = [];

    // Check if there is previously stored metadata (ETag and Last-Modified)
    if (file_exists(METADATA_FILE)) {
        $metadata = json_decode(file_get_contents(METADATA_FILE), true);
        if (isset($metadata['etag'])) {
            $headers['If-None-Match'] = $metadata['etag']; // Add the ETag header to the request
        }
        if (isset($metadata['last_modified'])) {
            $headers['If-Modified-Since'] = $metadata['last_modified']; // Add the Last-Modified header
        }
    }

    // Set up the HTTP context for the request (including timeout and conditional headers)
    $contextOptions = [
        'http' => [
            'method' => 'GET',
            'header' => array_map(function ($key, $value) {
                return "$key: $value";
            }, array_keys($headers), $headers),
            'timeout' => 5, // Timeout to avoid hanging if the list server is slow
        ]
    ];
    $context = stream_context_create($contextOptions);

    // Fetch the public suffix list, using conditional headers
    $response = @file_get_contents(PUBLIC_SUFFIX_LIST_URL, false, $context);

    // Check if the resource was successfully fetched
    if ($response === false) {
        // Log the error and return false (the script will fall back to the cached list or default behavior)
        error_log("Failed to fetch the public suffix list from " . PUBLIC_SUFFIX_LIST_URL);
        return false;
    }

    // Check if the resource was not modified (HTTP 304)
    $http_response_header = isset($http_response_header) ? $http_response_header : [];
    $statusCode = parseHttpStatusCode($http_response_header);

    if ($statusCode == 304) {
        // No update needed (resource has not changed)
        return true;
    }

    // If a new list was fetched, save it and update the metadata
    if ($statusCode == 200) {
        file_put_contents('public_suffix_list.dat', $response); // Save the list locally

        // Parse the headers for ETag and Last-Modified and save them
        $newMetadata = parseHttpHeadersForMetadata($http_response_header);
        file_put_contents(METADATA_FILE, json_encode($newMetadata));

        return true;
    }

    return false;
}

// Helper function to parse the HTTP status code from response headers
function parseHttpStatusCode($headers) {
    foreach ($headers as $header) {
        if (preg_match('/HTTP\/\d\.\d (\d{3})/', $header, $matches)) {
            return (int)$matches[1];
        }
    }
    return 200; // Default to 200 OK if no status code is found
}

// Helper function to extract ETag and Last-Modified headers from the HTTP response
function parseHttpHeadersForMetadata($headers) {
    $metadata = [];
    foreach ($headers as $header) {
        if (stripos($header, 'ETag:') === 0) {
            $metadata['etag'] = trim(substr($header, 5));
        }
        if (stripos($header, 'Last-Modified:') === 0) {
            $metadata['last_modified'] = trim(substr($header, 14));
        }
    }
    return $metadata;
}

// Function to load the locally cached Public Suffix List (or return null if unavailable)
function loadPublicSuffixList() {
    $filePath = 'public_suffix_list.dat';

    // Check if the list exists locally
    if (file_exists($filePath)) {
        $list = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        $suffixes = [];

        // Filter out comments and add the suffixes to the list
        foreach ($list as $line) {
            if (strpos($line, '//') === 0) continue; // Skip comments
            $suffixes[] = trim($line);
        }
        return $suffixes;
    }

    return null; // Return null if the list is not available
}

// Function to extract the main domain using the public suffix list
function extractMainDomainUsingSuffixList($domain, $suffixes) {
    $domainParts = explode('.', $domain);
    $count = count($domainParts);

    // If no suffix list is available, fall back to default two-part extraction
    if (!$suffixes) {
        return implode('.', array_slice($domainParts, -2));
    }

    // Check each part of the domain against the suffix list
    for ($i = 0; $i < $count - 1; $i++) {
        $possibleTLD = implode('.', array_slice($domainParts, $i));

        if (in_array($possibleTLD, $suffixes)) {
            // Return the registrable domain (SLD + TLD)
            return implode('.', array_slice($domainParts, $i - 1));
        }
    }

    // If no match is found, assume the last two parts are SLD + TLD
    return implode('.', array_slice($domainParts, -2));
}

// Detect domain availability from WHOIS output (Issue #3)
function detectAvailability($whoisText) {
    // First check: if key registration fields exist, domain is definitely registered
    if (preg_match('/Registrar:\s*\S+/i', $whoisText) ||
        preg_match('/Creation Date:\s*\S+/i', $whoisText) ||
        preg_match('/Created Date:\s*\S+/i', $whoisText) ||
        preg_match('/Registry Domain ID:\s*\S+/i', $whoisText)) {
        return 'registered';
    }

    // Second check: look for explicit "not found" indicators
    $notFoundPatterns = [
        '/^No match for /mi',
        '/^No match for domain/mi',
        '/^NOT FOUND\b/mi',
        '/^No Data Found/mi',
        '/^No entries found/mi',
        '/^Domain not found/mi',
        '/^The queried object does not exist/mi',
        '/^This query returned 0 objects/mi',
        '/^domain name not known/mi',
        '/^Object does not exist/mi',
        '/^Status:\s*free\b/mi',
        '/^%% No entries found/mi',
    ];
    foreach ($notFoundPatterns as $pattern) {
        if (preg_match($pattern, $whoisText)) {
            return 'available';
        }
    }
    return 'registered';
}

// Query DNS records for a domain (Issue #6)
function getDnsRecords($domain) {
    $records = [];
    $types = [DNS_A, DNS_AAAA, DNS_MX, DNS_NS, DNS_TXT, DNS_CNAME];
    $typeNames = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME'];
    foreach ($types as $i => $type) {
        $result = @dns_get_record($domain, $type);
        if ($result) {
            foreach ($result as $rec) {
                $entry = ['type' => $typeNames[$i]];
                switch ($type) {
                    case DNS_A:     $entry['value'] = $rec['ip'] ?? ''; break;
                    case DNS_AAAA:  $entry['value'] = $rec['ipv6'] ?? ''; break;
                    case DNS_MX:    $entry['value'] = $rec['target'] ?? ''; $entry['priority'] = $rec['pri'] ?? ''; break;
                    case DNS_NS:    $entry['value'] = $rec['target'] ?? ''; break;
                    case DNS_TXT:   $entry['value'] = $rec['txt'] ?? ''; break;
                    case DNS_CNAME: $entry['value'] = $rec['target'] ?? ''; break;
                }
                $records[] = $entry;
            }
        }
    }
    return $records;
}

// Parse WHOIS output into structured key fields (Issue #9)
function parseWhoisFields($whoisText) {
    $fields = [];
    $patterns = [
        'Domain Name'        => '/Domain Name:\s*(.+)/i',
        'Registrar'          => '/Registrar:\s*(.+)/i',
        'Creation Date'      => '/Creat(?:ion|ed) Date:\s*(.+)/i',
        'Expiry Date'        => '/Expir(?:y|ation) Date:\s*(.+)/i',
        'Updated Date'       => '/Updated Date:\s*(.+)/i',
        'Registrant Org'     => '/Registrant Organi[sz]ation:\s*(.+)/i',
        'Registrant Country' => '/Registrant Country:\s*(.+)/i',
        'Status'             => '/Domain Status:\s*(.+)/i',
    ];
    foreach ($patterns as $label => $regex) {
        if ($label === 'Status') {
            // Collect all statuses
            preg_match_all($regex, $whoisText, $matches);
            if (!empty($matches[1])) {
                $fields[$label] = array_map('trim', $matches[1]);
            }
        } else {
            if (preg_match($regex, $whoisText, $match)) {
                $fields[$label] = trim($match[1]);
            }
        }
    }
    // Collect nameservers
    preg_match_all('/Name Server:\s*(.+)/i', $whoisText, $nsMatches);
    if (!empty($nsMatches[1])) {
        $fields['Name Servers'] = array_map('trim', $nsMatches[1]);
    }
    // Calculate expiry countdown
    if (isset($fields['Expiry Date'])) {
        $expiryTime = strtotime($fields['Expiry Date']);
        if ($expiryTime) {
            $daysLeft = (int)ceil(($expiryTime - time()) / 86400);
            $fields['Expires In'] = $daysLeft . ' days';
        }
    }
    return $fields;
}

// RDAP lookup (Issue #12)
function rdapLookup($domain) {
    $rdapUrl = "https://rdap.org/domain/" . urlencode($domain);

    // Use curl for fast redirect handling (rdap.org 302s to registry servers)
    if (function_exists('curl_init')) {
        $ch = curl_init($rdapUrl);
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
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $httpCode >= 400) {
            return null;
        }
    } else {
        // Fallback to file_get_contents if curl unavailable
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => "Accept: application/rdap+json\r\n",
                'timeout' => 5,
                'follow_location' => 1,
                'max_redirects' => 5,
                'ignore_errors' => true,
            ]
        ]);
        $response = @file_get_contents($rdapUrl, false, $context);
        if ($response === false) {
            return null;
        }
    }

    $data = json_decode($response, true);
    if (!$data || isset($data['errorCode'])) {
        return null;
    }
    return $data;
}

// Format RDAP response into readable text (Issue #12)
function formatRdapResponse($rdap) {
    $lines = [];
    if (isset($rdap['ldhName'])) {
        $lines[] = "Domain Name: " . strtoupper($rdap['ldhName']);
    }
    if (isset($rdap['status'])) {
        foreach ($rdap['status'] as $status) {
            $lines[] = "Status: " . $status;
        }
    }
    if (isset($rdap['events'])) {
        foreach ($rdap['events'] as $event) {
            $action = ucfirst($event['eventAction'] ?? '');
            $date = $event['eventDate'] ?? '';
            $lines[] = "$action: $date";
        }
    }
    if (isset($rdap['entities'])) {
        foreach ($rdap['entities'] as $entity) {
            $roles = implode(', ', $entity['roles'] ?? []);
            $handle = $entity['handle'] ?? '';
            if ($roles) {
                $lines[] = ucfirst($roles) . ": " . $handle;
            }
            // Extract vcard info
            if (isset($entity['vcardArray'][1])) {
                foreach ($entity['vcardArray'][1] as $vcard) {
                    if ($vcard[0] === 'fn') {
                        $lines[] = "  Name: " . $vcard[3];
                    }
                    if ($vcard[0] === 'org') {
                        $lines[] = "  Organization: " . (is_array($vcard[3]) ? $vcard[3][0] : $vcard[3]);
                    }
                }
            }
        }
    }
    if (isset($rdap['nameservers'])) {
        foreach ($rdap['nameservers'] as $ns) {
            $lines[] = "Name Server: " . ($ns['ldhName'] ?? '');
        }
    }
    return implode("\n", $lines);
}

// Main logic for handling the WHOIS lookup request
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Determine response format (Issue #10)
    $jsonFormat = isset($_GET['format']) && $_GET['format'] === 'json';

    // Determine data source preference: ?source=rdap (default) or ?source=whois
    $sourceParam = isset($_GET['source']) ? strtolower($_GET['source']) : 'rdap';
    if (!in_array($sourceParam, ['rdap', 'whois'])) {
        $sourceParam = 'rdap';
    }
    // Also accept via POST (for form submissions)
    if (isset($_POST['source']) && in_array(strtolower($_POST['source']), ['rdap', 'whois'])) {
        $sourceParam = strtolower($_POST['source']);
    }

    // CSRF validation (Issue #1) - skip for JSON API requests
    if (!$jsonFormat && !validateCsrfToken()) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid request. Please refresh the page and try again.']);
        exit;
    }

    // Rate limiting (Issue #1)
    if (!checkRateLimit()) {
        header('Content-Type: application/json');
        http_response_code(429);
        echo json_encode(['error' => 'Rate limit exceeded. Please wait before trying again.']);
        exit;
    }

    // Attempt to update the public suffix list (will fallback if unable)
    if (!updatePublicSuffixList()) {
        error_log("Public suffix list could not be updated. Using local copy or default extraction.");
    }

    $suffixes = loadPublicSuffixList(); // Load the public suffix list
    $input = $_POST['domain'] ?? ''; // Get the domain input from the form

    // Step 1: Sanitize and extract the domain
    $domain = getDomainFromInput($input, $suffixes);

    // Step 2: Validate the extracted domain
    if (!$domain || !validateDomain($domain)) {
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid domain name.']);
        exit;
    }

    // Step 3: Check cache first (Issue #11)
    $whois_info = getCachedWhois($domain);
    $fromCache = ($whois_info !== null);

    // Step 4: Lookup using preferred source (Issue #12)
    // ?source=rdap (default): try RDAP first, fall back to WHOIS
    // ?source=whois: use WHOIS directly, skip RDAP
    $rdapData = null;
    $dataSource = 'whois';
    if (!$fromCache && $sourceParam === 'rdap') {
        $rdapData = rdapLookup($domain);
        if ($rdapData) {
            $dataSource = 'rdap';
            $whois_info = formatRdapResponse($rdapData);
        }
    }

    // Step 5: Fall back to WHOIS if RDAP skipped/failed/unavailable
    if (!$whois_info) {
        $escapedDomain = escapeshellarg($domain);
        $whois_info = shell_exec("whois $escapedDomain 2>&1");
        $dataSource = 'whois';
    }

    // Step 6: Cache the result (Issue #11)
    if ($whois_info && !$fromCache) {
        setCachedWhois($domain, $whois_info);
    }

    // Step 7: Detect availability (Issue #3)
    $availability = $whois_info ? detectAvailability($whois_info) : 'unknown';

    // Step 8: Parse structured fields (Issue #9)
    $parsedFields = $whois_info ? parseWhoisFields($whois_info) : [];

    // Step 9: Get DNS records (Issue #6)
    $dnsRecords = getDnsRecords($domain);

    // Step 10: Output result
    if ($jsonFormat) {
        // JSON API response (Issue #10)
        header('Content-Type: application/json');
        header('Access-Control-Allow-Origin: *');
        echo json_encode([
            'domain' => $domain,
            'availability' => $availability,
            'data_source' => $dataSource,
            'parsed' => $parsedFields,
            'dns' => $dnsRecords,
            'raw' => $whois_info ?: null,
            'cached' => $fromCache,
        ], JSON_PRETTY_PRINT);
    } else {
        // HTML response
        if (!$whois_info) {
            echo json_encode(['error' => 'Whois lookup failed or no information found.', 'availability' => 'unknown']);
        } else {
            echo json_encode([
                'whois' => htmlspecialchars($whois_info),
                'availability' => $availability,
                'data_source' => $dataSource,
                'parsed' => $parsedFields,
                'dns' => $dnsRecords,
                'cached' => $fromCache,
            ]);
        }
    }
}

// Function to extract and clean the domain from the user input
function getDomainFromInput($input, $suffixes) {
    $input = trim($input); // Remove any extra spaces
    $input = filter_var($input, FILTER_SANITIZE_URL); // Sanitize the input as a URL
    $parsedUrl = parse_url($input, PHP_URL_HOST); // Parse the hostname from the URL

    // If parsing fails, assume the input is a domain name
    if (!$parsedUrl) {
        $parsedUrl = $input;
    }

    // Remove 'www.' if present at the start
    if (strpos($parsedUrl, 'www.') === 0) {
        $parsedUrl = substr($parsedUrl, 4);
    }

    // Use the public suffix list to extract the main domain
    return extractMainDomainUsingSuffixList($parsedUrl, $suffixes);
}

// Function to validate the extracted domain (ensures the domain follows a valid structure)
function validateDomain($domain) {
    // Regular expression to validate domain format (e.g., example.com)
    $pattern = '/^(?!\-)(?:[a-zA-Z0-9\-]{1,63}\.)+(?:[a-zA-Z]{2,})$/';
    return preg_match($pattern, $domain);
}
?>