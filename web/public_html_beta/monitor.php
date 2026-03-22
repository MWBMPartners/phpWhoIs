<?php
/**
 * mwWhoIs — Domain Monitor (Issues #58, #62)
 *
 * Cron-based script that checks watched domains for WHOIS changes
 * and sends notifications via configured webhooks.
 *
 * Usage: php monitor.php
 * Recommended cron: 0 0,6,12,18 * * *  (every 6 hours)
 *
 * Watch list stored in: {CACHE_DIR}/watched_domains.json
 * Format: { "example.com": { "webhook": "https://...", "last_parsed": {...}, "added": "..." } }
 */

// ─── Bootstrap ───
define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');
define('CACHE_TTL', 900);
define('RATE_LIMIT_MAX', 30);
define('RATE_LIMIT_WINDOW', 60);

require_once __DIR__ . DIRECTORY_SEPARATOR . 'functions.php';

$watchFile = CACHE_DIR . DIRECTORY_SEPARATOR . 'watched_domains.json';
if (!file_exists($watchFile)) {
    echo "No watched domains configured.\n";
    exit(0);
}

$watched = json_decode(file_get_contents($watchFile), true);
if (!is_array($watched) || empty($watched)) {
    echo "No watched domains.\n";
    exit(0);
}

echo "Checking " . count($watched) . " watched domains...\n";

foreach ($watched as $domain => $config) {
    echo "  Checking: {$domain} ... ";

    // Perform WHOIS lookup
    $whoisText = shell_exec("whois " . escapeshellarg($domain) . " 2>&1");
    if (!$whoisText) {
        echo "FAILED (no response)\n";
        continue;
    }

    $parsed = parseWhois($whoisText);
    $lastParsed = isset($config['last_parsed']) ? $config['last_parsed'] : [];

    // Compare
    $changes = [];
    $monitoredFields = ['Registrar', 'Expiry Date', 'Name Servers', 'Status', 'Registrant Org'];
    foreach ($monitoredFields as $field) {
        $old = isset($lastParsed[$field]) ? (is_array($lastParsed[$field]) ? implode(', ', $lastParsed[$field]) : $lastParsed[$field]) : '';
        $new = isset($parsed[$field]) ? (is_array($parsed[$field]) ? implode(', ', $parsed[$field]) : $parsed[$field]) : '';
        if ($old !== $new) {
            $changes[] = [
                'field' => $field,
                'old' => $old ?: '(empty)',
                'new' => $new ?: '(empty)',
            ];
        }
    }

    // Update stored data
    $watched[$domain]['last_parsed'] = $parsed;
    $watched[$domain]['last_check'] = date('c');

    if (empty($changes)) {
        echo "no changes\n";
        continue;
    }

    echo count($changes) . " change(s) detected!\n";

    // Send webhook notification (Issue #58)
    $webhookUrl = isset($config['webhook']) ? $config['webhook'] : '';
    if ($webhookUrl) {
        $payload = json_encode([
            'domain' => $domain,
            'timestamp' => date('c'),
            'changes' => $changes,
            'current' => $parsed,
        ]);

        $ch = curl_init($webhookUrl);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_TIMEOUT => 10,
        ]);
        $result = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        echo "    Webhook sent (HTTP {$httpCode})\n";
        foreach ($changes as $c) {
            echo "    - {$c['field']}: {$c['old']} -> {$c['new']}\n";
        }
    }
}

// Save updated state
file_put_contents($watchFile, json_encode($watched, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
echo "Done.\n";
