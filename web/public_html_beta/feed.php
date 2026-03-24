<?php
/**
 * mwWhoIs — WHOIS Change RSS Feed (Issue #131)
 *
 * Returns an RSS feed of watched domain WHOIS changes.
 * Reads from the monitor.php change log in the cache directory.
 */

header('Content-Type: application/rss+xml; charset=utf-8');
header_remove('X-Powered-By');

define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

$appName = isset($app["Application"]["Name"]) ? $app["Application"]["Name"] : 'WHOIS Lookup';
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');

// Load watched domains and their history
$watchFile = CACHE_DIR . DIRECTORY_SEPARATOR . 'watched_domains.json';
$watched = file_exists($watchFile) ? json_decode(file_get_contents($watchFile), true) : [];

echo '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL;
?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title><?php echo htmlspecialchars($appName); ?> — Domain Changes</title>
    <link><?php echo htmlspecialchars($baseUrl); ?></link>
    <description>WHOIS change notifications for watched domains</description>
    <atom:link href="<?php echo htmlspecialchars($baseUrl . '/feed'); ?>" rel="self" type="application/rss+xml"/>
    <lastBuildDate><?php echo date('r'); ?></lastBuildDate>
<?php if (is_array($watched)): ?>
<?php foreach ($watched as $domain => $info): ?>
<?php if (!empty($info['last_check'])): ?>
    <item>
        <title>Checked: <?php echo htmlspecialchars($domain); ?></title>
        <link><?php echo htmlspecialchars($baseUrl . '/?domain=' . urlencode($domain)); ?></link>
        <description>Last checked: <?php echo htmlspecialchars($info['last_check']); ?></description>
        <pubDate><?php echo date('r', strtotime($info['last_check'])); ?></pubDate>
        <guid isPermaLink="false"><?php echo htmlspecialchars($domain . '-' . ($info['last_check'] ?? '')); ?></guid>
    </item>
<?php endif; ?>
<?php endforeach; ?>
<?php endif; ?>
</channel>
</rss>
