<?php
/**
 * mwWhoIs — Watched Domains RSS Feed (Issue #173)
 *
 * Returns an RSS feed of WHOIS changes for watched domains.
 * Reads from the monitor.php change log in the cache directory.
 *
 * Access: gated client-side by localStorage watchedDomains.
 * When the user account system (#163) is implemented, this endpoint
 * should also check $_SESSION['logged_in'] for server-side gating.
 */

require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'session_config.php';

header('Content-Type: application/rss+xml; charset=utf-8');
header('Cache-Control: public, max-age=900');
header_remove('X-Powered-By');

define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

$appName = isset($app["Application"]["Name"]) ? $app["Application"]["Name"] : 'WHOIS Lookup';
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');

// Load watched domains and their monitoring history
$watchFile = CACHE_DIR . DIRECTORY_SEPARATOR . 'watched_domains.json';
$watched = file_exists($watchFile) ? json_decode(file_get_contents($watchFile), true) : [];

// Load change history log (written by monitor.php)
$changeLogFile = CACHE_DIR . DIRECTORY_SEPARATOR . 'domain_changes.json';
$changeLog = file_exists($changeLogFile) ? json_decode(file_get_contents($changeLogFile), true) : [];

// Build items from change log (most recent first)
$items = [];
if (is_array($changeLog)) {
    // Reverse so newest entries come first
    $changeLog = array_reverse($changeLog);
    foreach (array_slice($changeLog, 0, 50) as $entry) {
        $domain = $entry['domain'] ?? 'unknown';
        $changes = $entry['changes'] ?? [];
        $ts = $entry['timestamp'] ?? '';

        // Note: not htmlspecialchars()'d here — this text is emitted inside a
        // CDATA section below, which must contain raw text, not HTML entities
        // (Issue #218: pre-escaping here caused readers to show literal &gt;/&amp;).
        $desc = '';
        foreach ($changes as $c) {
            $desc .= (($c['field'] ?? '') . ': ' . ($c['old'] ?? '') . ' → ' . ($c['new'] ?? '')) . "\n";
        }

        $items[] = [
            'title'       => 'WHOIS change: ' . $domain,
            'link'        => $baseUrl . '/?domain=' . urlencode($domain),
            'description' => $desc ?: 'Domain checked — no changes detected.',
            'date'        => $ts,
            'guid'        => $domain . '-' . $ts,
        ];
    }
}

// Also add watched domains with last_check as status items (if no change log)
if (empty($items) && is_array($watched)) {
    foreach ($watched as $domain => $info) {
        if (empty($info['last_check'])) {
            continue;
        }
        $items[] = [
            'title'       => 'Monitoring: ' . $domain,
            'link'        => $baseUrl . '/?domain=' . urlencode($domain),
            // Not htmlspecialchars()'d — emitted inside a CDATA section below.
            'description' => 'Last checked: ' . $info['last_check'],
            'date'        => $info['last_check'],
            'guid'        => $domain . '-' . $info['last_check'],
        ];
    }
}

echo '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL;
?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title><?php echo htmlspecialchars($appName); ?> — Watched Domains</title>
    <link><?php echo htmlspecialchars($baseUrl); ?></link>
    <description>WHOIS change notifications for your watched domains</description>
    <language>en</language>
    <atom:link href="<?php echo htmlspecialchars($baseUrl . '/feed-watchlist'); ?>" rel="self" type="application/rss+xml"/>
    <lastBuildDate><?php echo date('r'); ?></lastBuildDate>
<?php foreach ($items as $item): ?>
    <item>
        <title><?php echo htmlspecialchars($item['title']); ?></title>
        <link><?php echo htmlspecialchars($item['link']); ?></link>
        <description><![CDATA[<?php echo nl2br(str_replace(']]>', ']]]]><![CDATA[>', (string)$item['description'])); ?>]]></description>
        <pubDate><?php $ts = $item['date'] ? strtotime($item['date']) : false; echo date('r', $ts !== false ? $ts : time()); ?></pubDate>
        <guid isPermaLink="false"><?php echo htmlspecialchars($item['guid']); ?></guid>
    </item>
<?php endforeach; ?>
<?php if (empty($items)): ?>
    <item>
        <title>No watched domain activity yet</title>
        <link><?php echo htmlspecialchars($baseUrl); ?></link>
        <description>Add domains to your watchlist and run the monitor cron to see changes here.</description>
        <pubDate><?php echo date('r'); ?></pubDate>
        <guid isPermaLink="false">no-activity</guid>
    </item>
<?php endif; ?>
</channel>
</rss>
