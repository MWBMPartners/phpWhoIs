<?php
/**
 * mwWhoIs — Admin Dashboard (Issue #60)
 * Shows usage statistics: total lookups, cache hit rates, popular domains, error rates.
 *
 * Requires debug key authentication via config.php debug_key.
 */

require_once __DIR__ . DIRECTORY_SEPARATOR . 'session_config.php';

$config = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'config.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'config.php';
}

// ─── Auth check (reuse debug key) ───
$debugKey = isset($config['debug_key']) ? $config['debug_key'] : null;
if (!$debugKey || !isset($_GET['key']) || !hash_equals($debugKey, $_GET['key'])) {
    http_response_code(403);
    echo json_encode(['error' => 'Unauthorized. Provide ?key=<debug_key>']);
    exit;
}

require_once __DIR__ . DIRECTORY_SEPARATOR . 'functions.php';

if (!defined('CACHE_DIR')) {
    define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');
}

// ─── Collect stats ───
$stats = [];

// Cache stats
$cacheDir = CACHE_DIR;
$cacheFiles = is_dir($cacheDir) ? glob($cacheDir . '/*.json') : [];
$stats['cache'] = [
    'total_entries' => count($cacheFiles),
    'backend' => class_exists('Redis') ? 'redis' : (class_exists('Memcached') ? 'memcached' : 'file'),
];

// Rate limit stats
$rateLimitDir = $cacheDir . DIRECTORY_SEPARATOR . 'rate_limits';
$rateLimitFiles = is_dir($rateLimitDir) ? glob($rateLimitDir . '/*.json') : [];
$stats['rate_limits'] = [
    'active_sessions' => count($rateLimitFiles),
];

// Log stats
$logFile = __DIR__ . DIRECTORY_SEPARATOR . 'logs' . DIRECTORY_SEPARATOR . 'error.log';
$stats['errors'] = [
    'log_exists' => file_exists($logFile),
    'log_size' => file_exists($logFile) ? filesize($logFile) : 0,
    'recent_errors' => [],
];
if (file_exists($logFile)) {
    $lines = file($logFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $stats['errors']['total_lines'] = count($lines);
    $stats['errors']['recent_errors'] = array_slice($lines, -20);
}

// Lookup stats from stats file
$statsFile = $cacheDir . DIRECTORY_SEPARATOR . 'lookup_stats.json';
$lookupStats = file_exists($statsFile) ? json_decode(file_get_contents($statsFile), true) : [];
$stats['lookups'] = $lookupStats ?: [
    'total' => 0,
    'cache_hits' => 0,
    'rdap' => 0,
    'whois' => 0,
    'errors' => 0,
    'popular_domains' => [],
];

// API key stats
$apiKeysFile = $cacheDir . DIRECTORY_SEPARATOR . 'api_keys.json';
$apiKeys = file_exists($apiKeysFile) ? json_decode(file_get_contents($apiKeysFile), true) : [];
$stats['api_keys'] = [
    'total' => count($apiKeys),
];

// ─── Output format ───
if (isset($_GET['format']) && $_GET['format'] === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($stats, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

// App version info
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}
$appName = isset($app["Application"]["Name"]) ? $app["Application"]["Name"] : 'mwWhoIs';
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — Admin Dashboard</title>
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-4">
    <h1 class="mb-4"><i class="bi bi-speedometer2 me-2"></i><?php echo htmlspecialchars($appName); ?> — Admin Dashboard</h1>

    <div class="row g-3">
        <!-- Lookups -->
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title text-muted">Total Lookups</h5>
                    <p class="display-6"><?php echo number_format($stats['lookups']['total']); ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title text-muted">Cache Hits</h5>
                    <p class="display-6"><?php echo number_format($stats['lookups']['cache_hits']); ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title text-muted">Cached Entries</h5>
                    <p class="display-6"><?php echo $stats['cache']['total_entries']; ?></p>
                </div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card text-center">
                <div class="card-body">
                    <h5 class="card-title text-muted">Active Sessions</h5>
                    <p class="display-6"><?php echo $stats['rate_limits']['active_sessions']; ?></p>
                </div>
            </div>
        </div>
    </div>

    <!-- Cache backend -->
    <div class="card mt-4">
        <div class="card-header"><strong>System Info</strong></div>
        <div class="card-body">
            <table class="table table-sm mb-0">
                <tr><td class="fw-bold">Cache Backend</td><td><?php echo ucfirst($stats['cache']['backend']); ?></td></tr>
                <tr><td class="fw-bold">RDAP Lookups</td><td><?php echo number_format($stats['lookups']['rdap']); ?></td></tr>
                <tr><td class="fw-bold">WHOIS Lookups</td><td><?php echo number_format($stats['lookups']['whois']); ?></td></tr>
                <tr><td class="fw-bold">Errors</td><td><?php echo number_format($stats['lookups']['errors']); ?></td></tr>
                <tr><td class="fw-bold">API Keys Issued</td><td><?php echo $stats['api_keys']['total']; ?></td></tr>
                <tr><td class="fw-bold">Error Log Size</td><td><?php echo number_format($stats['errors']['log_size']); ?> bytes</td></tr>
            </table>
        </div>
    </div>

    <!-- Popular domains -->
    <?php if (!empty($stats['lookups']['popular_domains'])): ?>
    <div class="card mt-4">
        <div class="card-header"><strong>Popular Domains</strong></div>
        <div class="card-body">
            <table class="table table-sm table-striped mb-0">
                <thead><tr><th>Domain</th><th>Lookups</th></tr></thead>
                <tbody>
                <?php foreach (array_slice($stats['lookups']['popular_domains'], 0, 20, true) as $dom => $cnt): ?>
                    <tr><td><?php echo htmlspecialchars($dom); ?></td><td><?php echo number_format($cnt); ?></td></tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </div>
    <?php endif; ?>

    <!-- Recent errors -->
    <?php if (!empty($stats['errors']['recent_errors'])): ?>
    <div class="card mt-4">
        <div class="card-header"><strong>Recent Errors</strong> (last 20)</div>
        <div class="card-body">
            <pre class="mb-0 small" style="max-height:300px; overflow-y:auto;"><?php echo htmlspecialchars(implode("\n", $stats['errors']['recent_errors'])); ?></pre>
        </div>
    </div>
    <?php endif; ?>
</div>
</body>
</html>
