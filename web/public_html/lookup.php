<?php //https://chatgpt.com/share/66ed46d1-c1a4-800b-bc0a-93663c3084dd ?>
<?php
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

// Main logic for handling the WHOIS lookup request
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Attempt to update the public suffix list (will fallback if unable)
    if (!updatePublicSuffixList()) {
        error_log("Public suffix list could not be updated. Using local copy or default extraction.");
    }

    $suffixes = loadPublicSuffixList(); // Load the public suffix list
    $input = $_POST['domain']; // Get the domain input from the form

    // Step 1: Sanitize and extract the domain
    $domain = getDomainFromInput($input, $suffixes);

    // Step 2: Validate the extracted domain
    if (!$domain || !validateDomain($domain)) {
        echo "Invalid domain name.";
        exit;
    }

    // Step 3: Perform the WHOIS lookup using shell command
    $escapedDomain = escapeshellarg($domain); // Escape the domain for shell execution
    $whois_info = shell_exec("whois $escapedDomain");

    // Step 4: Output the WHOIS result
    if (!$whois_info) {
        echo "Whois lookup failed or no information found.";
    } else {
        echo "<pre>" . htmlspecialchars($whois_info) . "</pre>"; // HTML escape the result for safety
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