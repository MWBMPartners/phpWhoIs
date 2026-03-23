<?php
/**
 * mwWhoIs — Privacy Policy
 */

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}
header_remove('X-Powered-By');

$appName = isset($app["Application"]["Name"]) && $app["Application"]["Name"]
    ? $app["Application"]["Name"]
    : 'WHOIS Lookup';
$poweredBy = $appName;
if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]) {
    $poweredBy .= '/' . $app["Application"]["Version"]["Number"];
}
header('X-Powered-By: ' . $poweredBy);
$vendorName = isset($app["Application"]["Vendor"]["Parent"]["Name"]) && $app["Application"]["Vendor"]["Parent"]["Name"]
    ? $app["Application"]["Vendor"]["Parent"]["Name"]
    : 'MWBM Partners Ltd';
$vendorUrl = isset($app["Application"]["Vendor"]["Parent"]["Website"]["URL"]) && $app["Application"]["Vendor"]["Parent"]["Website"]["URL"]
    ? $app["Application"]["Vendor"]["Parent"]["Website"]["URL"]
    : '#';
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — Privacy Policy</title>
    <meta name="robots" content="noindex">
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo filemtime(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
</head>
<body>
    <header class="header-form" style="padding: 15px 20px;">
        <div class="d-flex align-items-center justify-content-between">
            <h1 class="mb-0" style="font-size: 1.2rem;">
                <a href="/"><img src="assets/images/logo-notext.svg" alt="" style="height: 32px; vertical-align: middle; margin-right: 8px;" aria-hidden="true"><?php echo htmlspecialchars($appName); ?></a>
                <small class="text-muted" style="font-weight: 400; font-size: 0.8em;">— Privacy Policy</small>
            </h1>
            <div class="d-flex gap-1">
                <a href="/" class="btn btn-sm btn-outline-secondary"><i class="bi bi-arrow-left"></i> Back</a>
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="themeToggle" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Change theme">
                        <i class="bi bi-sun-fill" id="themeIcon"></i>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="themeToggle" role="menu">
                        <li><button class="dropdown-item" type="button" data-theme-value="auto" role="menuitem"><i class="bi bi-circle-half me-2"></i>Auto</button></li>
                        <li><button class="dropdown-item" type="button" data-theme-value="light" role="menuitem"><i class="bi bi-sun-fill me-2"></i>Light</button></li>
                        <li><button class="dropdown-item" type="button" data-theme-value="dark" role="menuitem"><i class="bi bi-moon-fill me-2"></i>Dark</button></li>
                        <li><button class="dropdown-item" type="button" data-theme-value="colourblind" role="menuitem"><i class="bi bi-eye-fill me-2"></i>Colourblind</button></li>
                    </ul>
                </div>
            </div>
        </div>
    </header>

    <div class="subpage-content">
    <div class="container py-4" style="max-width: 800px; padding-bottom: 80px;">
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

    <h2 class="mt-4">5. Do Not Track (DNT)</h2>
    <p>We respect the <strong>Do Not Track</strong> signal sent by your browser. You can enable DNT in your browser's privacy settings at any time. When DNT is enabled (<code>DNT: 1</code>), the Service will:</p>
    <ul>
        <li>Skip all optional third-party requests (website screenshots, QR code generation via external APIs, IP geolocation lookups).</li>
        <li>Skip third-party security checks (Google Safe Browsing, VirusTotal, Have I Been Pwned) — these send the queried domain to external services.</li>
        <li>Disable anonymous usage statistics tracking (lookup counts, popular domains).</li>
        <li>Send a <code>Tk: N</code> (not tracking) response header to confirm compliance.</li>
    </ul>
    <p><strong>Please note:</strong> Enabling DNT will result in some features being unavailable or returning reduced data. Core lookup functionality remains unaffected, but supplementary features that rely on third-party services will be skipped. For a full list of what is and isn't available when DNT is enabled, please see <a href="terms#dnt-limitations">Section 5 of our Terms of Service</a>.</p>

    <h2 class="mt-4">6. Data Retention</h2>
    <ul>
        <li><strong>Cached lookups</strong> — automatically expire after 15 minutes.</li>
        <li><strong>Rate limit records</strong> — automatically cleaned up within minutes of expiry.</li>
        <li><strong>Server logs</strong> — retained according to standard hosting provider policies.</li>
        <li><strong>Browser data</strong> — persists until you clear it. We have no access to it.</li>
    </ul>

    <h2 class="mt-4">7. Your Rights</h2>
    <p>You have the right to:</p>
    <ul>
        <li>Clear your browser-stored data at any time.</li>
        <li>Use the tool without providing any personal information (domain names are public registry data).</li>
        <li>Request information about any data we hold related to your IP address.</li>
    </ul>

    <h2 class="mt-4">8. Security</h2>
    <p>We implement the following security measures:</p>
    <ul>
        <li>CSRF token protection on all form submissions</li>
        <li>Input validation and sanitisation to prevent injection attacks</li>
        <li>Rate limiting (per-session and per-IP) to prevent abuse</li>
        <li>Security headers (CSP, X-Frame-Options, X-Content-Type-Options)</li>
        <li>API keys stored as SHA-256 hashes, never in plain text</li>
        <li>Session hardening (HttpOnly, SameSite, secure cookies, periodic regeneration)</li>
    </ul>

    <h2 class="mt-4">9. Changes to This Policy</h2>
    <p>We may update this policy from time to time. The "Last updated" date at the top will reflect the most recent revision.</p>

    <h2 class="mt-4">10. Contact</h2>
    <p>For privacy-related enquiries, please contact <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a>.</p>
    </div>
    </div>

    <?php require __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'footer.php'; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    var themeIcon = document.getElementById('themeIcon');
    var theme = localStorage.getItem('theme') || 'auto';
    var systemDarkMQ = window.matchMedia('(prefers-color-scheme: dark)');
    applyTheme(theme);
    systemDarkMQ.addEventListener('change', function () { if (theme === 'auto') applyTheme('auto'); });
    document.querySelectorAll('[data-theme-value]').forEach(function (item) {
        item.addEventListener('click', function (e) { e.preventDefault(); theme = this.dataset.themeValue; applyTheme(theme); localStorage.setItem('theme', theme); });
    });
    function applyTheme(t) {
        var resolved = t;
        if (t === 'auto') resolved = systemDarkMQ.matches ? 'dark' : 'light';
        if (resolved === 'colourblind') { document.documentElement.setAttribute('data-bs-theme', 'light'); document.documentElement.setAttribute('data-theme', 'colourblind'); }
        else if (resolved === 'dark') { document.documentElement.setAttribute('data-bs-theme', 'dark'); document.documentElement.removeAttribute('data-theme'); }
        else { document.documentElement.setAttribute('data-bs-theme', 'light'); document.documentElement.removeAttribute('data-theme'); }
        var icons = { auto: 'bi bi-circle-half', light: 'bi bi-sun-fill', dark: 'bi bi-moon-fill', colourblind: 'bi bi-eye-fill' };
        themeIcon.className = icons[t] || 'bi bi-circle-half';
        document.querySelectorAll('[data-theme-value]').forEach(function (item) { item.classList.toggle('active', item.dataset.themeValue === t); });
    }
    </script>
</body>
</html>
