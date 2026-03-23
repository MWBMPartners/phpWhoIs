<?php
/**
 * Health check endpoint.
 * Returns application status, version, and diagnostic info.
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

// Load app version info
$app = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

// Check dependencies
$checks = [];

// PHP version
$checks['php'] = [
    'status' => version_compare(PHP_VERSION, '7.4.0', '>=') ? 'ok' : 'warning',
    'version' => PHP_VERSION,
];

// curl extension
$checks['curl'] = [
    'status' => function_exists('curl_init') ? 'ok' : 'warning',
    'detail' => function_exists('curl_init') ? 'available' : 'missing (RDAP will use file_get_contents fallback)',
];

// whois command
$whoisPath = trim(shell_exec('which whois 2>/dev/null') ?: '');
$checks['whois'] = [
    'status' => $whoisPath ? 'ok' : 'error',
    'detail' => $whoisPath ? $whoisPath : 'whois command not found',
];

// Session support
$checks['sessions'] = [
    'status' => session_status() !== PHP_SESSION_DISABLED ? 'ok' : 'error',
    'detail' => session_status() !== PHP_SESSION_DISABLED ? 'enabled' : 'disabled',
];

// Cache directory
$cacheDir = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache';
$cacheWritable = is_dir($cacheDir) && is_writable($cacheDir);
$cacheFiles = 0;
if (is_dir($cacheDir)) {
    $cacheFiles = count(glob($cacheDir . DIRECTORY_SEPARATOR . '*.json') ?: []);
}
$checks['cache'] = [
    'status' => $cacheWritable ? 'ok' : 'warning',
    'detail' => $cacheWritable ? 'writable' : 'not writable or missing',
    'cached_entries' => $cacheFiles,
];

// TLD data
$tldPath = __DIR__ . DIRECTORY_SEPARATOR . 'tlds.txt';
$suffixPath = __DIR__ . DIRECTORY_SEPARATOR . 'second_level_suffixes.txt';
$checks['tld_data'] = [
    'status' => (file_exists($tldPath) && file_exists($suffixPath)) ? 'ok' : 'warning',
    'tlds_file' => file_exists($tldPath) ? 'present (' . filesize($tldPath) . ' bytes)' : 'missing',
    'suffixes_file' => file_exists($suffixPath) ? 'present (' . filesize($suffixPath) . ' bytes)' : 'missing',
];

// Error log
$errorLogPath = __DIR__ . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'error.log';
$checks['error_log'] = [
    'status' => 'ok',
    'path' => $errorLogPath,
    'exists' => file_exists($errorLogPath),
];

// Overall status
$overallStatus = 'ok';
foreach ($checks as $check) {
    if ($check['status'] === 'error') {
        $overallStatus = 'error';
        break;
    }
    if ($check['status'] === 'warning') {
        $overallStatus = 'warning';
    }
}

// Version info
$version = 'unknown';
if (isset($app['Application']['Version']['Number'])) {
    $version = $app['Application']['Version']['Number'];
}
$devStatus = null;
if (isset($app['Application']['Version']['Development']['Status'])) {
    $devStatus = $app['Application']['Version']['Development']['Status'];
}

echo json_encode([
    'status' => $overallStatus,
    'version' => $version,
    'dev_status' => $devStatus,
    'timestamp' => date('c'),
    'checks' => $checks,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
