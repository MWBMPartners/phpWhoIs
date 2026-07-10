<?php
/**
 * mwWhoIs — Terms of Service
 */

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php');
}

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
    <title><?php echo htmlspecialchars($appName); ?> — Terms of Service</title>
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
                <small class="text-muted" style="font-weight: 400; font-size: 0.8em;">— Terms of Service</small>
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

    <p>By using <strong><?php echo htmlspecialchars($appName); ?></strong> ("the Service"), operated by <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a> (t/a MWservices) ("we", "us"), you agree to the following terms. If you do not agree, please do not use the Service.</p>

    <h2 class="mt-4">1. Acceptance of Terms</h2>
    <p>By accessing or using the Service — whether through the web interface or the JSON API — you confirm that you have read, understood, and agree to be bound by these Terms of Service and our <a href="privacy">Privacy Policy</a>. If you are using the Service on behalf of an organisation, you confirm you have the authority to bind that organisation to these terms.</p>

    <h2 class="mt-4">2. Service Description</h2>
    <p>The Service is a <strong>free</strong> domain-intelligence tool providing WHOIS/RDAP lookups, DNS record queries, SSL/TLS certificate information, email security checks, IP geolocation, subdomain discovery, and related checks, via a web interface and a JSON API. The Service is provided <strong>"as is"</strong>, on a best-effort basis, with no subscription fee for standard use.</p>

    <h2 class="mt-4">3. Acceptable Use</h2>
    <p>You agree to use the Service only for lawful, legitimate purposes. You must not:</p>
    <ul>
        <li><strong>Abuse rate limits</strong> — attempt to bypass, circumvent, or overwhelm the published rate limits (whether the session/IP limits or the tier assigned to your API key).</li>
        <li><strong>Scrape or automate beyond the API</strong> — use automated tools, bots, or scripts against the web interface in place of the documented JSON API and its keys; bulk lookups must stay within the documented limits.</li>
        <li><strong>Facilitate attacks or unauthorised probing</strong> — use the Service to plan, assist, or carry out attacks, security scans, or probes against systems or domains you do not own or are not authorised to test.</li>
        <li><strong>Send unsolicited communications</strong> — use data obtained through the Service to send spam, unsolicited marketing, or to facilitate harassment of any individual or organisation.</li>
        <li><strong>Overload or disrupt the Service</strong> — attempt to disrupt, overload, or circumvent the Service's rate-limiting or other security controls, or gain unauthorised access to its servers or connected networks.</li>
        <li><strong>Misrepresent identity</strong> — impersonate others or misrepresent your affiliation when using the Service.</li>
    </ul>

    <h2 class="mt-4">4. API Terms</h2>
    <p>The JSON API is available for programmatic access, subject to:</p>
    <ul>
        <li>The rate limits and tiers described in the <a href="docs">API documentation</a>, which may change from time to time.</li>
        <li>API keys, if issued, being personal to you — they must not be shared or published, and are stored on our server only as a SHA-256 hash.</li>
        <li>Our right to revoke API keys or restrict access at any time for abuse, or violation of these terms, without prior notice.</li>
    </ul>

    <h2 class="mt-4">5. Accuracy Disclaimer</h2>
    <p>The Service aggregates WHOIS, RDAP, DNS, and other data from external registries and third-party sources described in our <a href="privacy">Privacy Policy</a>. This data:</p>
    <ul>
        <li>May be <strong>incomplete, outdated, or inaccurate</strong> — we merely relay what these external sources return, and do not independently verify it.</li>
        <li>Is <strong>not authoritative</strong> and does <strong>not constitute legal, financial, or professional advice</strong> of any kind.</li>
        <li>Should be independently verified with the relevant registry or registrar before you rely on it for any decision (e.g. purchasing a domain, assessing a security posture, or forming a legal view).</li>
        <li>May be up to 15 minutes old where served from our cache.</li>
    </ul>

    <h2 class="mt-4">6. Third-Party Sources</h2>
    <p>The Service integrates with numerous third-party APIs and data sources, listed in our <a href="privacy">Privacy Policy</a> (including RDAP/WHOIS providers, DNS resolvers, certificate-transparency logs, geolocation, reverse-IP, screenshot, and — where configured — threat-intelligence services). Each of these is subject to its own terms of service, and we do not guarantee their availability, accuracy, or continued operation. We are not responsible for their data-handling practices.</p>

    <h2 class="mt-4" id="dnt-limitations">7. Do Not Track (DNT) &amp; Reduced Functionality</h2>
    <p>The Service respects the <strong>Do Not Track</strong> (DNT) signal sent by your browser. You may enable DNT in your browser settings at any time. However, enabling DNT will result in certain features being unavailable or returning reduced data, as the Service will skip all optional third-party requests to honour your privacy preference.</p>
    <p><strong>The following features are unavailable when DNT is enabled:</strong></p>
    <ul>
        <li><strong>IP Geolocation</strong> — Server location data (city, country, ISP, AS number) will not be displayed, as this requires a request to an external geolocation service.</li>
        <li><strong>Website Screenshots</strong> — Preview images of looked-up domains will not be generated, as this uses an external screenshot service.</li>
        <li><strong>Google Safe Browsing</strong> — Malware and phishing warnings will not be shown, as this requires sending the domain to Google's API.</li>
        <li><strong>VirusTotal Reputation</strong> — Domain reputation scores and antivirus verdicts will not be available.</li>
        <li><strong>Have I Been Pwned (HIBP)</strong> — Data breach information for the domain will not be retrieved.</li>
        <li><strong>QR Code Sharing</strong> — QR codes will not be generated, as this uses an external QR code API. The share URL will still be displayed as text.</li>
        <li><strong>Usage Statistics</strong> — Your lookups will not be counted in aggregate usage statistics (this has no user-facing impact).</li>
    </ul>
    <p><strong>The following features remain fully available with DNT enabled:</strong></p>
    <ul>
        <li>WHOIS and RDAP domain lookups</li>
        <li>DNS record queries (A, AAAA, MX, NS, TXT, CNAME)</li>
        <li>SSL/TLS certificate information</li>
        <li>Email security checks (SPF, DMARC, DKIM)</li>
        <li>Subdomain discovery</li>
        <li>Domain availability detection</li>
        <li>Bulk lookups and domain comparison</li>
        <li>All export features (JSON, CSV, copy, download)</li>
        <li>Registrar reputation checks (uses local data only)</li>
    </ul>
    <p>We believe this is a fair balance between respecting your privacy and providing a useful service. If you require the full feature set, you may disable DNT in your browser settings.</p>

    <h2 class="mt-4">8. Intellectual Property</h2>
    <p>The Service, its design, code, and branding are the intellectual property of <?php echo htmlspecialchars($vendorName); ?>. You may not copy, modify, distribute, or create derivative works of the Service without prior written permission.</p>
    <p>WHOIS and DNS data returned by the Service is subject to the terms and policies of the respective registries and registrars that provide it.</p>

    <h2 class="mt-4">9. Domain Registration</h2>
    <p>The Service may display links to register available domains through third-party registrars. We do not guarantee domain availability, pricing, or the quality of service provided by any linked registrar. Domain registration transactions are between you and the registrar.</p>

    <h2 class="mt-4">10. No Warranty</h2>
    <p>The Service is provided <strong>"as is"</strong> and <strong>"as available"</strong>, without warranties of any kind, whether express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, non-infringement, or that the Service will be uninterrupted, secure, or error-free.</p>

    <h2 class="mt-4">11. Limitation of Liability</h2>
    <p>To the fullest extent permitted by law, we shall not be liable for any direct, indirect, incidental, special, consequential, or punitive damages arising from your use of, or inability to use, the Service, including but not limited to:</p>
    <ul>
        <li>Decisions made based on WHOIS data, domain availability results, or any other data returned by the Service.</li>
        <li>Loss of data or business interruption.</li>
        <li>Inaccurate, incomplete, or outdated information.</li>
        <li>Actions, omissions, or unavailability of third-party services integrated with the Service.</li>
    </ul>
    <p>Nothing in these terms excludes or limits liability that cannot lawfully be excluded or limited (for example, liability for death or personal injury caused by negligence, or for fraud).</p>

    <h2 class="mt-4">12. Indemnity</h2>
    <p>You agree to indemnify and hold us harmless from any claims, losses, liabilities, damages, and expenses (including reasonable legal fees) arising out of your breach of these terms, your misuse of the Service, or your violation of any applicable law or third-party right.</p>

    <h2 class="mt-4">13. Changes to the Service</h2>
    <p>We reserve the right to modify, suspend, or discontinue the Service (or any part of it), including individual features, API tiers, or rate limits, at any time, with or without notice.</p>

    <h2 class="mt-4">14. Termination</h2>
    <p>We may restrict or terminate your access to the Service at any time if we believe you have violated these terms, without prior notice or liability.</p>

    <h2 class="mt-4">15. Changes to These Terms</h2>
    <p>We may update these terms from time to time. Continued use of the Service after changes constitutes acceptance of the revised terms. The "Last updated" date at the top will reflect the most recent revision.</p>

    <h2 class="mt-4">16. Governing Law</h2>
    <p>These terms are governed by and construed in accordance with the laws of <strong>England and Wales</strong>. Any disputes arising out of or relating to these terms or the Service shall be subject to the exclusive jurisdiction of the courts of England and Wales.</p>

    <h2 class="mt-4">17. Contact</h2>
    <p>For enquiries regarding these terms, please contact <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a>.</p>

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
