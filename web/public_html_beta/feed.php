<?php
/**
 * mwWhoIs — RSS Feed (Issue #131)
 *
 * Returns an RSS feed of recent application changes, parsed from
 * CHANGELOG.md. Each changelog entry becomes an RSS item.
 */

header('Content-Type: application/rss+xml; charset=utf-8');
header('Cache-Control: public, max-age=3600');
header_remove('X-Powered-By');

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

$appName = isset($app["Application"]["Name"]) ? $app["Application"]["Name"] : 'WHOIS Lookup';
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http')
    . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');

// Parse CHANGELOG.md into RSS items
$changelogPath = __DIR__ . DIRECTORY_SEPARATOR . 'CHANGELOG.md';
$items = [];

if (file_exists($changelogPath)) {
    $lines = file($changelogPath, FILE_IGNORE_NEW_LINES);
    $current = null;

    foreach ($lines as $line) {
        // Each entry starts with: ## [hash] - YYYY-MM-DD
        if (preg_match('/^## \[([a-f0-9]+)\] - (\d{4}-\d{2}-\d{2})/', $line, $m)) {
            if ($current) {
                $current['description'] = trim($current['description']);
                $items[] = $current;
            }
            $current = [
                'hash'        => $m[1],
                'date'        => $m[2],
                'title'       => '',
                'description' => '',
                'link'        => '',
            ];
            continue;
        }

        if (!$current) continue;

        // Title line: **feat: some description**
        if (!$current['title'] && preg_match('/^\*\*(.+)\*\*/', $line, $m)) {
            $current['title'] = $m[1];
            continue;
        }

        // Commit URL line
        if (preg_match('/Commit: \[`[a-f0-9]+`\]\((.+)\)/', $line, $m)) {
            $current['link'] = $m[1];
            continue;
        }

        // Skip header lines, accumulate the rest as description
        if (strpos($line, '# Changelog') === 0) continue;
        if (strpos($line, 'All notable changes') === 0) continue;
        if (strpos($line, 'This changelog is') === 0) continue;

        $current['description'] .= $line . "\n";
    }

    // Don't forget the last entry
    if ($current) {
        $current['description'] = trim($current['description']);
        $items[] = $current;
    }
}

// Limit to most recent 20 entries
$items = array_slice($items, 0, 20);

echo '<?xml version="1.0" encoding="UTF-8"?>' . PHP_EOL;
?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
    <title><?php echo htmlspecialchars($appName); ?> — Updates</title>
    <link><?php echo htmlspecialchars($baseUrl); ?></link>
    <description>Recent changes and updates to <?php echo htmlspecialchars($appName); ?></description>
    <language>en</language>
    <atom:link href="<?php echo htmlspecialchars($baseUrl . '/feed'); ?>" rel="self" type="application/rss+xml"/>
    <lastBuildDate><?php echo date('r'); ?></lastBuildDate>
<?php foreach ($items as $item): ?>
    <item>
        <title><?php echo htmlspecialchars($item['title'] ?: 'Update ' . $item['hash']); ?></title>
        <link><?php echo htmlspecialchars($item['link'] ?: $baseUrl); ?></link>
        <description><![CDATA[<?php echo nl2br(htmlspecialchars($item['description'])); ?>]]></description>
        <pubDate><?php echo date('r', strtotime($item['date'])); ?></pubDate>
        <guid isPermaLink="false"><?php echo htmlspecialchars($item['hash']); ?></guid>
    </item>
<?php endforeach; ?>
<?php if (empty($items)): ?>
    <item>
        <title>Welcome to <?php echo htmlspecialchars($appName); ?></title>
        <link><?php echo htmlspecialchars($baseUrl); ?></link>
        <description>No updates yet. Check back soon!</description>
        <pubDate><?php echo date('r'); ?></pubDate>
        <guid isPermaLink="false">welcome</guid>
    </item>
<?php endif; ?>
</channel>
</rss>
