<?php
/**
 * mwWhoIs — Privacy Policy
 */

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

$appName = isset($app["Application"]["Name"]) && $app["Application"]["Name"]
    ? $app["Application"]["Name"]
    : 'WHOIS Lookup';
$vendorName = isset($app["Application"]["Vendor"]["Parent"]["Name"]) && $app["Application"]["Vendor"]["Parent"]["Name"]
    ? $app["Application"]["Vendor"]["Parent"]["Name"]
    : 'MWBM Partners Ltd';
$vendorUrl = isset($app["Application"]["Vendor"]["Parent"]["Website"]["URL"]) && $app["Application"]["Vendor"]["Parent"]["Website"]["URL"]
    ? $app["Application"]["Vendor"]["Parent"]["Website"]["URL"]
    : '#';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — Privacy Policy</title>
    <meta name="robots" content="noindex">
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo filemtime(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
</head>
<body>
<div class="container py-4" style="max-width: 800px;">
    <h1 class="mb-4">Privacy Policy</h1>
    <p class="text-muted">Last updated: <?php echo date('j F Y'); ?></p>

    <p><strong><?php echo htmlspecialchars($appName); ?></strong> is operated by <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a>. This policy explains what data we collect, how we use it, and your rights.</p>

    <h2 class="mt-4">1. Data We Collect</h2>

    <h3>1.1 Data You Provide</h3>
    <ul>
        <li><strong>Domain names and IP addresses</strong> you enter for WHOIS/RDAP lookups.</li>
        <li><strong>API keys</strong> if you use the authenticated JSON API.</li>
    </ul>

    <h3>1.2 Data Collected Automatically</h3>
    <ul>
        <li><strong>IP address</strong> — used for rate limiting to prevent abuse. IP addresses are stored as one-way hashes, not in plain text.</li>
        <li><strong>Session data</strong> — a session cookie is used for CSRF protection and rate limiting. It contains no personal information.</li>
        <li><strong>Server logs</strong> — standard web server logs may record IP addresses, timestamps, and requested URLs for operational and security purposes.</li>
    </ul>

    <h3>1.3 Data Stored in Your Browser</h3>
    <p>The following data is stored in your browser's <code>localStorage</code> and never sent to our servers:</p>
    <ul>
        <li><strong>Lookup history</strong> — your last 10 looked-up domains.</li>
        <li><strong>WHOIS timeline</strong> — snapshots of parsed WHOIS data for change tracking.</li>
        <li><strong>Watch list</strong> — domains you choose to monitor for expiry.</li>
        <li><strong>Theme preference</strong> — your selected colour theme (light/dark/colourblind/auto).</li>
        <li><strong>Language preference</strong> — your selected display language.</li>
    </ul>
    <p>You can clear all browser-stored data at any time using your browser's settings or the "Clear history" button in the application.</p>

    <h2 class="mt-4">2. How We Use Your Data</h2>
    <ul>
        <li><strong>Domain lookups</strong> — to query public WHOIS/RDAP registries, DNS servers, and SSL certificate authorities on your behalf.</li>
        <li><strong>Rate limiting</strong> — to prevent abuse and ensure fair access for all users.</li>
        <li><strong>Caching</strong> — lookup results are cached for up to 15 minutes to improve performance and reduce load on external registries.</li>
        <li><strong>Usage statistics</strong> — aggregate, anonymised lookup counts (total lookups, cache hit rates, popular domains) may be tracked for operational monitoring. No personally identifiable information is included.</li>
    </ul>

    <h2 class="mt-4">3. Third-Party Services</h2>
    <p>When you perform a lookup, the domain or IP you enter may be sent to the following external services:</p>
    <ul>
        <li><strong>Public WHOIS servers</strong> — via the system <code>whois</code> command.</li>
        <li><strong>RDAP</strong> — via <code>rdap.org</code>, a public RDAP aggregation service.</li>
        <li><strong>IP geolocation</strong> — via <code>ip-api.com</code> for server location data.</li>
        <li><strong>Google Safe Browsing</strong> — if configured, to check for known malicious domains.</li>
        <li><strong>VirusTotal</strong> — if configured, for domain reputation data.</li>
        <li><strong>Have I Been Pwned</strong> — if configured, for data breach information.</li>
        <li><strong>Thum.io</strong> — if enabled, for website screenshot previews.</li>
        <li><strong>QR Server</strong> — via <code>api.qrserver.com</code> for QR code generation.</li>
    </ul>
    <p>Each third-party service is subject to its own privacy policy. We do not control what data these services retain.</p>

    <h2 class="mt-4">4. Cookies</h2>
    <p>We use a single <strong>session cookie</strong> (PHP session ID) for:</p>
    <ul>
        <li>CSRF (Cross-Site Request Forgery) protection</li>
        <li>Session-based rate limiting</li>
    </ul>
    <p>This cookie is <code>HttpOnly</code>, <code>SameSite=Lax</code>, and <code>Secure</code> (when served over HTTPS). It does not track you across websites and is deleted when you close your browser. We do not use advertising or analytics cookies.</p>

    <h2 class="mt-4">5. Data Retention</h2>
    <ul>
        <li><strong>Cached lookups</strong> — automatically expire after 15 minutes.</li>
        <li><strong>Rate limit records</strong> — automatically cleaned up within minutes of expiry.</li>
        <li><strong>Server logs</strong> — retained according to standard hosting provider policies.</li>
        <li><strong>Browser data</strong> — persists until you clear it. We have no access to it.</li>
    </ul>

    <h2 class="mt-4">6. Your Rights</h2>
    <p>You have the right to:</p>
    <ul>
        <li>Clear your browser-stored data at any time.</li>
        <li>Use the tool without providing any personal information (domain names are public registry data).</li>
        <li>Request information about any data we hold related to your IP address.</li>
    </ul>

    <h2 class="mt-4">7. Security</h2>
    <p>We implement the following security measures:</p>
    <ul>
        <li>CSRF token protection on all form submissions</li>
        <li>Input validation and sanitisation to prevent injection attacks</li>
        <li>Rate limiting (per-session and per-IP) to prevent abuse</li>
        <li>Security headers (CSP, X-Frame-Options, X-Content-Type-Options)</li>
        <li>API keys stored as SHA-256 hashes, never in plain text</li>
        <li>Session hardening (HttpOnly, SameSite, secure cookies, periodic regeneration)</li>
    </ul>

    <h2 class="mt-4">8. Changes to This Policy</h2>
    <p>We may update this policy from time to time. The "Last updated" date at the top will reflect the most recent revision.</p>

    <h2 class="mt-4">9. Contact</h2>
    <p>For privacy-related enquiries, please contact <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a>.</p>

    <hr class="mt-5">
    <p class="text-muted small"><a href="/">&larr; Back to <?php echo htmlspecialchars($appName); ?></a></p>
</div>
</body>
</html>
