<?php
/**
 * mwWhoIs — Privacy Policy
 */

require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'asset_version.php';
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
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo assetVersion(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
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
    <p class="text-muted">Last updated: 10 July 2026</p>

    <p><strong><?php echo htmlspecialchars($appName); ?></strong> is a free, ad-free domain WHOIS/RDAP lookup and domain-intelligence tool operated by <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a> (t/a MWservices). There are no user accounts and we keep no database of users. This policy explains, in plain terms, what data is involved when you use the Service, how it is used, and your rights.</p>

    <h2 class="mt-4">1. What This Service Is</h2>
    <p>The Service lets you look up public WHOIS/RDAP registration data, DNS records, SSL/TLS certificates, email security configuration, and related information for domains and IP addresses that you enter. It is free to use, carries no advertising, and does not require you to create an account.</p>

    <h2 class="mt-4">2. Data You Submit</h2>
    <ul>
        <li><strong>Domain names and IP addresses</strong> you enter are used to perform the lookup you requested, and are sent to the external data sources described in Section 4 below to fulfil that lookup.</li>
        <li><strong>API keys</strong>, if you use the authenticated JSON API, are stored on our server only as a SHA-256 hash — never in plain text.</li>
    </ul>

    <h2 class="mt-4">3. Server-Side Data</h2>
    <ul>
        <li><strong>IP address</strong> — your IP address is used transiently for abuse prevention and rate limiting. It is stored only as a hashed value in a short-lived server-side file, and is not retained in plain text. Your IP address may also appear in standard web-server logs, retained according to our hosting provider's normal log-rotation policy.</li>
        <li><strong>Session cookie</strong> — a single first-party session cookie is used for CSRF (Cross-Site Request Forgery) protection and session-based rate limiting. It is <code>HttpOnly</code>, <code>SameSite=Lax</code>, and <code>Secure</code> (when served over HTTPS). This cookie is <strong>not</strong> used for tracking or advertising, contains no personal information, and is deleted when you close your browser.</li>
        <li><strong>Lookup cache</strong> — results of a lookup are cached on the server for approximately 15 minutes to speed up repeat queries and reduce load on external registries, then automatically expire.</li>
        <li><strong>Usage statistics</strong> — only aggregate, non-identifying counts (e.g. total lookups performed) are kept for basic operational monitoring. No personally identifiable information is included.</li>
    </ul>

    <h2 class="mt-4">4. Third-Party Data Sources</h2>
    <p>To fulfil a lookup, the domain or IP address you enter may be sent to one or more of the following external services. Many of these are only contacted for optional, supplementary checks, and <strong>all of them are skipped when your browser sends a Do Not Track signal</strong> (see Section 5).</p>
    <ul>
        <li><strong>RDAP and WHOIS</strong> — the RDAP aggregation service at <code>rdap.org</code>, and the relevant registry/registrar WHOIS servers, to retrieve domain registration data.</li>
        <li><strong>DNS resolvers</strong> — including public DNS resolvers, to retrieve DNS records and check propagation.</li>
        <li><strong>Certificate Transparency logs</strong> — via <code>crt.sh</code>, for SSL/TLS certificate history.</li>
        <li><strong>IP geolocation</strong> — via <code>ip-api.com</code>, for server location data.</li>
        <li><strong>Reverse-IP lookup</strong> — via <code>hackertarget.com</code>, for co-hosted domain discovery.</li>
        <li><strong>Website screenshots</strong> — via <code>thum.io</code>, for preview images.</li>
        <li><strong>The target website itself</strong> — for HTTP header, technology-stack, <code>robots.txt</code>, and redirect checks.</li>
        <li><strong>Mail servers</strong> — for SMTP-related email security checks.</li>
        <li><strong>DNS blocklists</strong> — including Spamhaus and other DNS blocklist providers, for reputation checks.</li>
        <li><strong>Optional security-intelligence services</strong> — Google Safe Browsing, VirusTotal, Have I Been Pwned, Shodan, AbuseIPDB, PhishTank, and URLhaus, but only where the site operator has configured API keys for these.</li>
    </ul>
    <p>In addition, reference data about top-level domains is periodically refreshed from <strong>IANA</strong> and <strong>publicsuffix.org</strong>, and front-end assets (Bootstrap, icons) are loaded from the <strong>jsDelivr</strong> CDN when you load a page. Each third-party service is subject to its own privacy policy; we do not control what data these services retain.</p>

    <h2 class="mt-4">5. Do Not Track (DNT)</h2>
    <p>The Service <strong>honours</strong> the Do Not Track signal sent by your browser. When DNT is enabled, all optional third-party enrichment calls listed in Section 4 are skipped, and anonymous usage-statistics tracking is disabled. Core WHOIS/RDAP/DNS lookup functionality is unaffected. For a full breakdown of what is and isn't available with DNT enabled, see <a href="terms#dnt-limitations">Section 7 of our Terms of Service</a>.</p>

    <h2 class="mt-4">6. Data Stored in Your Browser Only</h2>
    <p>The following data is stored using your browser's <code>localStorage</code> and is <strong>never sent to our servers</strong>:</p>
    <ul>
        <li><strong>Lookup history</strong> — domains you have recently looked up.</li>
        <li><strong>Watch list</strong> — domains you choose to monitor for expiry.</li>
        <li><strong>Change-history timeline</strong> — snapshots of past lookups, used to show what has changed over time.</li>
        <li><strong>Security-score history</strong> — past security-score results for domains you have checked.</li>
        <li><strong>Settings and preferences</strong> — such as your theme and language choices.</li>
    </ul>
    <p>You can clear this data at any time from your browser's settings, or using the relevant "clear" controls within the application. We have no access to this data.</p>

    <h2 class="mt-4">7. No Advertising, No Third-Party Analytics</h2>
    <p>The Service carries no advertising and does not use third-party analytics or tracking scripts. We do not sell, rent, or share your data with third parties for marketing purposes.</p>

    <h2 class="mt-4">8. Your Rights (UK GDPR)</h2>
    <p>We process a minimal amount of personal data — principally your IP address, transiently, for the purpose of preventing abuse and enforcing rate limits. Our lawful basis for this is <strong>legitimate interest</strong> in keeping the Service secure, available, and fair to all users. Because we hold no accounts and no persistent personal-data store beyond short-lived, hashed rate-limiting records and standard server logs, most data-subject requests will find little or nothing held about you. If you have questions about this policy or wish to raise a data-protection query, please contact us via <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a> (t/a MWservices).</p>

    <h2 class="mt-4">9. Children</h2>
    <p>The Service is a general-purpose technical utility and is not directed at children. We do not knowingly collect personal data from children.</p>

    <h2 class="mt-4">10. Changes to This Policy</h2>
    <p>We may update this policy from time to time to reflect changes to the Service or our data practices. The "Last updated" date at the top of this page will reflect the most recent revision.</p>

    <h2 class="mt-4">11. Contact</h2>
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
    systemDarkMQ.addEventListener('change', function () {
        if (theme === 'auto') {
            applyTheme('auto');
        }
    });
    document.querySelectorAll('[data-theme-value]').forEach(function (item) {
        item.addEventListener('click', function (e) {
            e.preventDefault();
            theme = this.dataset.themeValue;
            applyTheme(theme);
            localStorage.setItem('theme', theme);
        });
    });
    function applyTheme(t) {
        var resolved = t;
        if (t === 'auto') {
            resolved = systemDarkMQ.matches ? 'dark' : 'light';
        }
        if (resolved === 'colourblind') {
            document.documentElement.setAttribute('data-bs-theme', 'light');
            document.documentElement.setAttribute('data-theme', 'colourblind');
        } else if (resolved === 'dark') {
            document.documentElement.setAttribute('data-bs-theme', 'dark');
            document.documentElement.removeAttribute('data-theme');
        } else {
            document.documentElement.setAttribute('data-bs-theme', 'light');
            document.documentElement.removeAttribute('data-theme');
        }
        var icons = { auto: 'bi bi-circle-half', light: 'bi bi-sun-fill', dark: 'bi bi-moon-fill', colourblind: 'bi bi-eye-fill' };
        themeIcon.className = icons[t] || 'bi bi-circle-half';
        document.querySelectorAll('[data-theme-value]').forEach(function (item) {
            item.classList.toggle('active', item.dataset.themeValue === t);
        });
    }
    </script>
</body>
</html>
