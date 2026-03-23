<?php
/**
 * mwWhoIs — Terms of Service
 */

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}
header_remove('X-Powered-By');

$appName = isset($app["Application"]["Name"]) && $app["Application"]["Name"]
    ? $app["Application"]["Name"]
    : 'WHOIS Lookup';
header('X-Powered-By: ' . $appName);
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
    <title><?php echo htmlspecialchars($appName); ?> — Terms of Service</title>
    <meta name="robots" content="noindex">
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo filemtime(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
</head>
<body>
<div class="container py-4" style="max-width: 800px;">
    <h1 class="mb-4">Terms of Service</h1>
    <p class="text-muted">Last updated: <?php echo date('j F Y'); ?></p>

    <p>By using <strong><?php echo htmlspecialchars($appName); ?></strong> ("the Service"), operated by <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a> ("we", "us"), you agree to the following terms.</p>

    <h2 class="mt-4">1. Service Description</h2>
    <p>The Service provides free domain WHOIS/RDAP lookups, DNS record queries, SSL/TLS certificate information, email security checks, IP geolocation, subdomain discovery, and related domain intelligence tools. The Service is provided via a web interface and a JSON API.</p>

    <h2 class="mt-4">2. Acceptable Use</h2>
    <p>You agree to use the Service only for lawful purposes. You must not:</p>
    <ul>
        <li><strong>Abuse rate limits</strong> — Do not attempt to bypass, circumvent, or overwhelm the rate limiting mechanisms (30 requests per 60 seconds per session/IP, or as configured for your API key tier).</li>
        <li><strong>Automate excessively</strong> — Automated queries must respect rate limits. Bulk lookups are limited to 50 domains per request.</li>
        <li><strong>Harvest data for spam</strong> — Do not use WHOIS data obtained through the Service to send unsolicited communications, spam, or for marketing purposes.</li>
        <li><strong>Attack or probe</strong> — Do not use the Service to conduct security scans, vulnerability assessments, or attacks against domains you do not own or have authorisation to test.</li>
        <li><strong>Misrepresent identity</strong> — Do not impersonate others or misrepresent your affiliation when using the Service.</li>
        <li><strong>Interfere with the Service</strong> — Do not attempt to disrupt, overload, or gain unauthorised access to the Service, its servers, or connected networks.</li>
    </ul>

    <h2 class="mt-4">3. API Usage</h2>
    <p>The JSON API is available for programmatic access. Use of the API is subject to:</p>
    <ul>
        <li>Rate limits as described in the <a href="docs">API documentation</a>.</li>
        <li>API keys, if issued, are personal and must not be shared or published.</li>
        <li>We reserve the right to revoke API keys or restrict access at any time for abuse or violation of these terms.</li>
    </ul>

    <h2 class="mt-4">4. Data Accuracy</h2>
    <p>The Service queries public WHOIS registries, RDAP servers, DNS infrastructure, and third-party data sources. We do not guarantee the accuracy, completeness, or timeliness of any data returned. Specifically:</p>
    <ul>
        <li>WHOIS and RDAP data is provided by domain registries and registrars — we merely relay it.</li>
        <li>Domain availability results are indicative, not authoritative. Always verify with the relevant registrar before making purchasing decisions.</li>
        <li>Security assessments (Safe Browsing, VirusTotal, HIBP) rely on third-party databases and may not reflect the current state.</li>
        <li>Cached results may be up to 15 minutes old.</li>
    </ul>

    <h2 class="mt-4" id="dnt-limitations">5. Do Not Track (DNT) &amp; Reduced Functionality</h2>
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

    <h2 class="mt-4">6. Intellectual Property</h2>
    <p>The Service, its design, code, and branding are the intellectual property of <?php echo htmlspecialchars($vendorName); ?>. You may not copy, modify, distribute, or create derivative works of the Service without prior written permission.</p>
    <p>WHOIS and DNS data returned by the Service is subject to the terms and policies of the respective registries and registrars that provide it.</p>

    <h2 class="mt-4">7. Third-Party Services</h2>
    <p>The Service integrates with third-party APIs and data sources (RDAP, ip-api.com, Google Safe Browsing, VirusTotal, Have I Been Pwned, Thum.io, QR Server). Your use of features powered by these services is also subject to their respective terms of service. We are not responsible for their availability, accuracy, or data handling practices.</p>

    <h2 class="mt-4">8. Domain Registration</h2>
    <p>The Service may display links to register available domains through third-party registrars. We do not guarantee domain availability, pricing, or the quality of service provided by any linked registrar. Domain registration transactions are between you and the registrar.</p>

    <h2 class="mt-4">9. Limitation of Liability</h2>
    <p>The Service is provided <strong>"as is"</strong> and <strong>"as available"</strong> without warranties of any kind, whether express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, or non-infringement.</p>
    <p>To the fullest extent permitted by law, we shall not be liable for any direct, indirect, incidental, special, consequential, or punitive damages arising from your use of, or inability to use, the Service, including but not limited to:</p>
    <ul>
        <li>Decisions made based on WHOIS data or domain availability results.</li>
        <li>Loss of data or business interruption.</li>
        <li>Inaccurate, incomplete, or outdated information.</li>
        <li>Actions of third-party services integrated with the Service.</li>
    </ul>

    <h2 class="mt-4">10. Service Availability</h2>
    <p>We do not guarantee uninterrupted or error-free operation of the Service. We reserve the right to modify, suspend, or discontinue the Service (or any part of it) at any time, with or without notice.</p>

    <h2 class="mt-4">11. Termination</h2>
    <p>We may restrict or terminate your access to the Service at any time if we believe you have violated these terms, without prior notice or liability.</p>

    <h2 class="mt-4">12. Changes to These Terms</h2>
    <p>We may update these terms from time to time. Continued use of the Service after changes constitutes acceptance of the revised terms. The "Last updated" date at the top will reflect the most recent revision.</p>

    <h2 class="mt-4">13. Governing Law</h2>
    <p>These terms are governed by and construed in accordance with the laws of England and Wales. Any disputes shall be subject to the exclusive jurisdiction of the courts of England and Wales.</p>

    <h2 class="mt-4">14. Contact</h2>
    <p>For enquiries regarding these terms, please contact <a href="<?php echo htmlspecialchars($vendorUrl); ?>"><?php echo htmlspecialchars($vendorName); ?></a>.</p>

    <hr class="mt-5">
    <p class="text-muted small"><a href="/">&larr; Back to <?php echo htmlspecialchars($appName); ?></a></p>
</div>
</body>
</html>
