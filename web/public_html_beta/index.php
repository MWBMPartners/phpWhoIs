<?php
/**
 * mwWhoIs - Domain WHOIS/RDAP Lookup Tool
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ─── Session & CSRF ───
require_once __DIR__ . DIRECTORY_SEPARATOR . 'session_config.php';
$csrfToken = $_SESSION['csrf_token'];

// ─── Security headers ───
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// ─── Config ───
$config = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'config.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'config.php';
}

// ─── Debug mode (requires matching debug key from config) ───
$modeDev = false;
$modeDebug = false;

if (isset($_GET['dev'])) {
    $debugKey = isset($config['debug_key']) ? $config['debug_key'] : null;
    if ($debugKey && isset($_GET['key']) && hash_equals($debugKey, $_GET['key'])) {
        $modeDev = true;

        if (isset($_GET['debug'])) {
            $modeDebug = true;
        }
    }
}

if ($modeDebug) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
}

// ─── App version info ───
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

// ─── Copyright helper ───
if (isset($app["Application"]["Copyright"]["Year"]["Start"])
    && is_numeric($app["Application"]["Copyright"]["Year"]["Start"])
    && $app["Application"]["Copyright"]["Year"]["Start"] < date("Y")) {
    $copyrightYear = $app["Application"]["Copyright"]["Year"]["Start"] . "-" . date("Y");
} else {
    $copyrightYear = date("Y");
}

if (isset($app["Application"]["Vendor"]["Parent"]["Name"]) && $app["Application"]["Vendor"]["Parent"]["Name"]) {
    $copyrightOwner = $app["Application"]["Vendor"]["Parent"]["Name"];
} elseif (isset($app["Application"]["Vendor"]["Name"]) && $app["Application"]["Vendor"]["Name"]) {
    $copyrightOwner = $app["Application"]["Vendor"]["Name"];
} elseif (isset($app["Application"]["Name"]) && $app["Application"]["Name"]) {
    $copyrightOwner = $app["Application"]["Name"];
} else {
    $copyrightOwner = null;
}
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
<?php
    $pageTitle = NULL;
    if (isset($app["Application"]["Name"]) && $app["Application"]["Name"]) {
        $pageTitle = $app["Application"]["Name"];
    } else {
        $pageTitle = 'WHOIS Lookup';
    }
    if (isset($app["Application"]["Version"]["Development"]["Status"]) && $app["Application"]["Version"]["Development"]["Status"]) {
        $pageTitle .= ' (' . $app["Application"]["Version"]["Development"]["Status"] . ')';
    }
    if (isset($app["Application"]["Description"]["Synopsis"]) && $app["Application"]["Description"]["Synopsis"]) {
        $pageDescription = $app["Application"]["Description"]["Synopsis"];
    }
    else {
        $pageDescription = 'Free domain WHOIS and RDAP lookup tool. Check domain registration, availability, DNS records, expiry dates, and registrar information.';
    }
    
    $pageUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
?>
    <title><?php echo htmlspecialchars($pageTitle); ?></title>
    <meta name="description" content="<?php echo htmlspecialchars($pageDescription); ?>">
    <meta name="robots" content="index, follow">
    <link rel="canonical" href="<?php echo htmlspecialchars(strtok($pageUrl, '?')); ?>">

    <!-- Open Graph -->
    <meta property="og:type" content="website">
    <meta property="og:title" content="<?php echo htmlspecialchars($pageTitle); ?>">
    <meta property="og:description" content="<?php echo htmlspecialchars($pageDescription); ?>">
    <meta property="og:url" content="<?php echo htmlspecialchars($pageUrl); ?>">

    <!-- Twitter Card -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="<?php echo htmlspecialchars($pageTitle); ?>">
    <meta name="twitter:description" content="<?php echo htmlspecialchars($pageDescription); ?>">

    <!-- CSRF token for JS -->
    <meta name="csrf-token" content="<?php echo htmlspecialchars($csrfToken); ?>">

    <!-- Favicons: SVG > PNG > ICO > GIF (priority order) -->
    <link rel="icon" type="image/svg+xml" href="favicon.svg">
    <link rel="icon" type="image/png" sizes="512x512" href="favicon.png">
    <link rel="icon" type="image/x-icon" href="favicon.ico">
    <link rel="icon" type="image/gif" href="favicon.gif">
    <link rel="apple-touch-icon" href="favicon.png">
    <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css?v=<?php echo filemtime(__DIR__ . DIRECTORY_SEPARATOR . 'style.css'); ?>">
</head>
<body>
    <!-- Header -->
    <div class="header-form">
        <div class="position-relative text-center mb-2">
            <h1 class="mb-0"><a href="/"><?php if(isset($app["Application"]["Name"]) && $app["Application"]["Name"]){ echo $app["Application"]["Name"];}else{ echo "Whois Lookup";}if(isset($app["Application"]["Version"]["Development"]["Status"]) && $app["Application"]["Version"]["Development"]["Status"]){echo " <span style=\"font-size: 0.7em\">(".$app["Application"]["Version"]["Development"]["Status"].")</span>";} ?></a></h1>
            <button class="btn btn-sm btn-outline-secondary position-absolute top-50 end-0 translate-middle-y" id="darkModeToggle" title="Toggle dark mode">
                <i class="bi bi-moon-fill" id="darkModeIcon"></i>
            </button>
        </div>

        <!-- Lookup mode tabs -->
        <ul class="nav nav-tabs mb-3" id="lookupModeTabs">
            <li class="nav-item"><a class="nav-link active" href="#" data-mode="single">Single Lookup</a></li>
            <li class="nav-item"><a class="nav-link" href="#" data-mode="bulk">Bulk Lookup</a></li>
        </ul>

        <!-- Single domain form -->
        <form id="whoisForm" class="form-container">
            <div class="form-group flex-grow-1">
                <label for="domain" class="visually-hidden">Domain or URL</label>
                <input type="text" class="form-control" id="domain" name="domain"
                    title="Please enter a valid domain name, e.g., example.com"
                    placeholder="example.com" required autocomplete="off">
            </div>
            <button type="submit" class="btn btn-primary submit-btn">Lookup</button>
        </form>

        <!-- Bulk domain form -->
        <form id="bulkWhoisForm" class="form-container" style="display:none;">
            <div class="form-group flex-grow-1">
                <label for="bulkDomains" class="visually-hidden">Domains (one per line)</label>
                <textarea class="form-control" id="bulkDomains" name="domains" rows="4"
                    placeholder="example.com&#10;example.org&#10;example.net" required></textarea>
            </div>
            <button type="submit" class="btn btn-primary submit-btn">Lookup All</button>
        </form>

        <!-- Recent lookups -->
        <div id="historyContainer" class="mt-2" style="display:none;">
            <div class="d-flex align-items-center gap-2">
                <small class="text-muted">Recent:</small>
                <div id="historyList" class="d-flex flex-wrap gap-1"></div>
                <button class="btn btn-sm btn-link text-muted p-0" id="clearHistory" title="Clear history">
                    <i class="bi bi-x-circle"></i>
                </button>
            </div>
        </div>
    </div>

    <!-- Results section -->
    <div class="result-container" id="resultContainer">
        <!-- Empty state -->
        <div id="emptyState" class="text-center py-5">
            <i class="bi bi-search" style="font-size: 3rem; opacity: 0.15;"></i>
            <p class="mt-3 text-muted">Enter a domain above to get started</p>
        </div>

        <div id="loadingSpinner" class="text-center py-5" style="display:none;">
            <div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>
            <p class="mt-2 text-muted">Looking up domain information...</p>
        </div>

        <div id="availabilityBadge" class="mb-3" style="display:none;"></div>
        <div id="dataSourceBadge" class="mb-2" style="display:none;"></div>
        <div id="parsedFields" class="mb-3" style="display:none;"></div>

        <ul class="nav nav-pills mb-3" id="resultTabs" style="display:none;">
            <li class="nav-item"><a class="nav-link active" href="#" data-tab="whois">WHOIS</a></li>
            <li class="nav-item"><a class="nav-link" href="#" data-tab="dns">DNS Records</a></li>
            <li class="nav-item"><a class="nav-link" href="#" data-tab="email">Email Security</a></li>
            <li class="nav-item"><a class="nav-link" href="#" data-tab="ssl">SSL/TLS</a></li>
        </ul>

        <div id="whoisResultPane"><div id="result"></div></div>
        <div id="dnsResultPane" style="display:none;"></div>
        <div id="emailSecurityPane" style="display:none;"></div>
        <div id="sslPane" style="display:none;"></div>

        <div id="actionButtons" class="mt-2 d-flex gap-2 flex-wrap" style="display:none !important;">
            <button class="btn btn-secondary btn-sm" id="toggleViewBtn">Show Raw Whois</button>
            <button class="btn btn-outline-secondary btn-sm" id="copyBtn"><i class="bi bi-clipboard"></i> Copy</button>
            <button class="btn btn-outline-secondary btn-sm" id="downloadBtn"><i class="bi bi-download"></i> Download</button>
            <a href="#" target="_blank" class="btn btn-outline-secondary btn-sm" id="waybackBtn"><i class="bi bi-clock-history"></i> Wayback Machine</a>
            <button class="btn btn-outline-secondary btn-sm" id="qrCodeBtn"><i class="bi bi-qr-code"></i> QR Code</button>
        </div>

        <!-- QR Code modal (Issue #50) -->
        <div id="qrCodeModal" class="modal fade" tabindex="-1">
            <div class="modal-dialog modal-sm modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Share Lookup</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body text-center">
                        <img id="qrCodeImg" src="QR Code" alt="QR Code" style="max-width:100%;">
                        <p class="small text-muted mt-2" id="qrCodeUrl"></p>
                    </div>
                </div>
            </div>
        </div>

        <div id="bulkResults" class="accordion mt-3" style="display:none;"></div>

        <!-- Bulk export buttons (Issue #49) -->
        <div id="bulkExportButtons" class="mt-2 d-flex gap-2" style="display:none;">
            <button class="btn btn-outline-secondary btn-sm" id="exportCsvBtn"><i class="bi bi-filetype-csv"></i> Export CSV</button>
            <button class="btn btn-outline-secondary btn-sm" id="exportJsonBtn"><i class="bi bi-filetype-json"></i> Export JSON</button>
        </div>
    </div>

    <!-- Footer -->
    <div class="footer">
        <div class="footer-row">
            <div class="footer-left">
                Privacy Policy | Terms of Use
            </div>
            <div class="footer-right">
                <?php
                    echo $pageTitle;
                    
                    if (isset($app["Application"]["Version"]["Version"]) && $app["Application"]["Version"]["Version"]){
                        echo " v" . htmlspecialchars($app["Application"]["Version"]["Version"]);

                        if (!empty($app["Application"]["Version"]["Development"]["Status"])){
                            echo " " . htmlspecialchars($app["Application"]["Version"]["Development"]["Status"]);
                        }

                        if (!empty($app["Application"]["Version"]["Repo"]["Commit"]["Short"])){
                            echo ' (<a href="' . htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["URL"]) . '" target="_blank" class="footer-commit">';
                            echo htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["Short"]);
                            echo '</a>';

                            if (!empty($app["Application"]["Version"]["Repo"]["Commit"]["Date"])){
                                echo ' ' . htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["Date"]);
                            }

                            echo nl2br(")".PHP_EOL);
                        }
                    }
                ?>
                &copy; <?php echo htmlspecialchars("$copyrightYear $copyrightOwner"); ?>. All Rights Reserved
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var CSRF = '<?php echo htmlspecialchars($csrfToken); ?>';
        var REG_CONFIG = <?php echo json_encode(isset($config['registration']) ? $config['registration'] : ['enabled' => false]); ?>;
        var formattedResult = '';
        var rawWhoisText = '';
        var isRawView = false;

        // HTML escape helper to prevent XSS
        function esc(str) {
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
        }
        var currentDomain = '';

        // ── Dark mode ──
        var darkToggle = document.getElementById('darkModeToggle');
        var darkIcon = document.getElementById('darkModeIcon');
        var theme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-bs-theme', theme);
        setIcon(theme);

        darkToggle.addEventListener('click', function () {
            theme = theme === 'dark' ? 'light' : 'dark';
            document.documentElement.setAttribute('data-bs-theme', theme);
            localStorage.setItem('theme', theme);
            setIcon(theme);
        });
        function setIcon(t) { darkIcon.className = t === 'dark' ? 'bi bi-sun-fill' : 'bi bi-moon-fill'; }

        // ── Lookup mode tabs ──
        document.querySelectorAll('#lookupModeTabs .nav-link').forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelectorAll('#lookupModeTabs .nav-link').forEach(function (t) { t.classList.remove('active'); });
                this.classList.add('active');
                var single = this.dataset.mode === 'single';
                document.getElementById('whoisForm').style.display = single ? '' : 'none';
                document.getElementById('bulkWhoisForm').style.display = single ? 'none' : '';
            });
        });

        // ── History ──
        function getHistory() { try { return JSON.parse(localStorage.getItem('whoisHistory') || '[]'); } catch (e) { return []; } }
        function saveToHistory(domain) {
            var h = getHistory().filter(function (x) { return x.domain !== domain; });
            h.unshift({ domain: domain, ts: Date.now() });
            if (h.length > 10) h = h.slice(0, 10);
            localStorage.setItem('whoisHistory', JSON.stringify(h));
            renderHistory();
        }
        function renderHistory() {
            var h = getHistory(), c = document.getElementById('historyContainer'), l = document.getElementById('historyList');
            if (!h.length) { c.style.display = 'none'; return; }
            c.style.display = '';
            l.innerHTML = h.map(function (x) {
                return '<button class="btn btn-sm btn-outline-primary history-item" data-domain="' + esc(x.domain) + '">' + esc(x.domain) + '</button>';
            }).join('');
            l.querySelectorAll('.history-item').forEach(function (btn) {
                btn.addEventListener('click', function () {
                    document.getElementById('domain').value = this.dataset.domain;
                    triggerLookup(this.dataset.domain);
                    updateURL(this.dataset.domain);
                });
            });
        }
        document.getElementById('clearHistory').addEventListener('click', function () { localStorage.removeItem('whoisHistory'); renderHistory(); });
        renderHistory();

        // ── URL param auto-lookup ──
        var urlDomain = new URLSearchParams(window.location.search).get('domain');
        if (urlDomain) { document.getElementById('domain').value = urlDomain; triggerLookup(urlDomain); }

        // ── Single form submit ──
        document.getElementById('whoisForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var d = document.getElementById('domain').value.trim();
            if (d) { triggerLookup(d); updateURL(d); }
        });

        // ── Bulk form submit ──
        document.getElementById('bulkWhoisForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var text = document.getElementById('bulkDomains').value.trim();
            if (!text) return;
            var domains = text.split(/[\n,]+/).map(function (d) { return d.trim(); }).filter(Boolean);
            if (domains.length) triggerBulkLookup(domains);
        });

        // ── Main lookup ──
        function triggerLookup(domain) {
            currentDomain = domain;
            showLoading(true);
            hideResults();

            var fd = new FormData();
            fd.append('domain', domain);
            fd.append('csrf_token', CSRF);

            fetch('lookup.php?nocache=' + Date.now(), { method: 'POST', body: fd })
                .then(function (r) { if (!r.ok) throw new Error('Server error: ' + r.status); return r.json(); })
                .then(function (data) {
                    showLoading(false);
                    if (data.error) { showError(data.error); return; }
                    rawWhoisText = data.whois || '';
                    displayResults(data);
                    saveToHistory(domain);
                })
                .catch(function (err) { showLoading(false); showError('Lookup failed: ' + err.message); });
        }

        // ── Bulk lookup ──
        var bulkResultsData = [];

        function triggerBulkLookup(domains) {
            showLoading(true);
            hideResults();
            bulkResultsData = [];
            var acc = document.getElementById('bulkResults');
            acc.innerHTML = '';
            acc.style.display = '';
            var done = 0;

            domains.forEach(function (domain, i) {
                setTimeout(function () {
                    var fd = new FormData();
                    fd.append('domain', domain);
                    fd.append('csrf_token', CSRF);

                    fetch('lookup.php?nocache=' + Date.now(), { method: 'POST', body: fd })
                        .then(function (r) { return r.json(); })
                        .then(function (data) {
                            // Store for export (Issue #49)
                            bulkResultsData.push({ domain: domain, data: data });

                            var badgeClass = data.availability === 'available' ? 'bg-success' : 'bg-info';
                            var badgeText = data.availability === 'available' ? 'Available' : 'Registered';
                            var regBtn = '';
                            if (data.availability === 'available' && REG_CONFIG.enabled) {
                                var bulkRegUrl = REG_CONFIG.url_template.replace('{domain}', encodeURIComponent(domain));
                                var bulkTarget = REG_CONFIG.open_in_new_tab ? ' target="_blank"' : '';
                                regBtn = ' <a href="' + bulkRegUrl + '"' + bulkTarget + ' class="btn btn-success btn-sm ms-2"><i class="bi bi-cart-plus me-1"></i>' + REG_CONFIG.button_text + '</a>';
                            }
                            var item = document.createElement('div');
                            item.className = 'accordion-item';
                            item.innerHTML =
                                '<h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#bulk-' + i + '">' +
                                esc(domain) + ' <span class="badge ' + badgeClass + ' ms-2">' + badgeText + '</span>' + regBtn +
                                '</button></h2>' +
                                '<div id="bulk-' + i + '" class="accordion-collapse collapse"><div class="accordion-body"><pre>' +
                                esc(data.whois || data.error || 'No data') + '</pre></div></div>';
                            acc.appendChild(item);
                        })
                        .catch(function () {})
                        .finally(function () {
                            if (++done === domains.length) {
                                showLoading(false);
                                if (bulkResultsData.length > 0) {
                                    document.getElementById('bulkExportButtons').style.display = '';
                                }
                            }
                        });
                }, i * 1000);
            });
        }

        // ── Bulk export (Issue #49) ──
        document.getElementById('exportCsvBtn').addEventListener('click', function () {
            if (bulkResultsData.length === 0) { return; }
            var csv = 'Domain,Availability,Registrar,Creation Date,Expiry Date,Data Source\n';
            bulkResultsData.forEach(function (r) {
                var p = r.data.parsed || {};
                csv += '"' + r.domain + '","' + (r.data.availability || '') + '","' +
                    (p['Registrar'] || '') + '","' + (p['Creation Date'] || '') + '","' +
                    (p['Expiry Date'] || '') + '","' + (r.data.data_source || '') + '"\n';
            });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
            a.download = 'whois-bulk-export.csv';
            a.click();
            URL.revokeObjectURL(a.href);
        });

        document.getElementById('exportJsonBtn').addEventListener('click', function () {
            if (bulkResultsData.length === 0) { return; }
            var jsonData = bulkResultsData.map(function (r) {
                return { domain: r.domain, availability: r.data.availability, parsed: r.data.parsed, dns: r.data.dns, data_source: r.data.data_source };
            });
            var a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([JSON.stringify(jsonData, null, 2)], { type: 'application/json' }));
            a.download = 'whois-bulk-export.json';
            a.click();
            URL.revokeObjectURL(a.href);
        });

        // ── Display results ──
        function displayResults(data) {
            // Availability badge
            var avBadge = document.getElementById('availabilityBadge');
            if (data.availability === 'available') {
                var regButton = '';
                if (REG_CONFIG.enabled) {
                    var regUrl = REG_CONFIG.url_template.replace('{domain}', encodeURIComponent(currentDomain));
                    var regTarget = REG_CONFIG.open_in_new_tab ? ' target="_blank"' : '';
                    regButton = '<a href="' + regUrl + '"' + regTarget + ' class="btn btn-success btn-sm"><i class="bi bi-cart-plus me-1"></i>' + REG_CONFIG.button_text + '</a>';
                }
                avBadge.innerHTML = '<div class="alert alert-success d-flex align-items-center justify-content-between flex-wrap gap-2">' +
                    '<div><i class="bi bi-check-circle-fill me-2"></i><strong>' + esc(currentDomain) + '</strong> appears to be available!</div>' +
                    regButton + '</div>';
            } else {
                avBadge.innerHTML = '<div class="alert alert-info d-flex align-items-center"><i class="bi bi-info-circle-fill me-2"></i><strong>' + esc(currentDomain) + '</strong>&nbsp;is registered.</div>';
            }
            avBadge.style.display = '';

            // Source badge
            var dsBadge = document.getElementById('dataSourceBadge');
            dsBadge.innerHTML = '<span class="badge bg-secondary">Source: ' + (data.data_source || 'whois').toUpperCase() + (data.cached ? ' (cached)' : '') + '</span>';
            dsBadge.style.display = '';

            // Parsed fields card
            if (data.parsed && Object.keys(data.parsed).length) {
                var pf = document.getElementById('parsedFields');
                var html = '<div class="card"><div class="card-header"><strong>Domain Summary</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                for (var key in data.parsed) {
                    var val = Array.isArray(data.parsed[key]) ? data.parsed[key].join(', ') : data.parsed[key];
                    var cls = '';
                    if (key === 'Expires In') {
                        var days = parseInt(val);
                        if (days <= 30) cls = ' class="table-danger"';
                        else if (days <= 90) cls = ' class="table-warning"';
                    }
                    html += '<tr' + cls + '><td class="fw-bold">' + key + '</td><td>' + val + '</td></tr>';
                }
                html += '</table></div></div>';
                pf.innerHTML = html;
                pf.style.display = '';
            }

            // IP geolocation (Issue #18)
            if (data.geolocation) {
                var geo = data.geolocation;
                var geoHtml = '<div class="card mt-3"><div class="card-header"><strong>Server Location</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                if (geo.city) { geoHtml += '<tr><td class="fw-bold">City</td><td>' + geo.city + '</td></tr>'; }
                if (geo.country) { geoHtml += '<tr><td class="fw-bold">Country</td><td>' + geo.country + ' (' + geo.country_code + ')</td></tr>'; }
                if (geo.isp) { geoHtml += '<tr><td class="fw-bold">ISP</td><td>' + geo.isp + '</td></tr>'; }
                if (geo.org) { geoHtml += '<tr><td class="fw-bold">Organization</td><td>' + geo.org + '</td></tr>'; }
                if (geo.as) { geoHtml += '<tr><td class="fw-bold">AS</td><td>' + geo.as + '</td></tr>'; }
                geoHtml += '</table></div></div>';
                document.getElementById('parsedFields').innerHTML += geoHtml;
                document.getElementById('parsedFields').style.display = '';
            }

            // Formatted WHOIS
            formatWhoisData(data.whois || '');

            // DNS records
            if (data.dns && data.dns.length) {
                document.getElementById('resultTabs').style.display = '';
                var dnsHtml = '<table class="table table-striped table-sm"><thead><tr><th>Type</th><th>Value</th><th>Priority</th></tr></thead><tbody>';
                data.dns.forEach(function (r) {
                    dnsHtml += '<tr><td><span class="badge bg-secondary">' + r.type + '</span></td><td>' + r.value + '</td><td>' + (r.priority || '') + '</td></tr>';
                });
                dnsHtml += '</tbody></table>';
                document.getElementById('dnsResultPane').innerHTML = dnsHtml;
            }

            // Email security (Issue #56)
            if (data.email_security && Object.keys(data.email_security).length) {
                document.getElementById('resultTabs').style.display = '';
                var es = data.email_security;
                var esHtml = '<div class="card"><div class="card-header"><strong>Email Security</strong></div><div class="card-body"><table class="table table-sm mb-0">';

                // SPF
                var spfIcon = es.spf.found ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
                esHtml += '<tr><td class="fw-bold">' + spfIcon + ' SPF</td><td>' + (es.spf.status || 'missing') + '</td></tr>';
                if (es.spf.record) {
                    esHtml += '<tr><td></td><td><code class="small">' + es.spf.record + '</code></td></tr>';
                }

                // DMARC
                var dmarcIcon = es.dmarc.found ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
                esHtml += '<tr><td class="fw-bold">' + dmarcIcon + ' DMARC</td><td>' + (es.dmarc.status || 'missing') + '</td></tr>';
                if (es.dmarc.record) {
                    esHtml += '<tr><td></td><td><code class="small">' + es.dmarc.record + '</code></td></tr>';
                }

                // DKIM
                var dkimIcon = es.dkim.found ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-exclamation-triangle-fill text-warning"></i>';
                esHtml += '<tr><td class="fw-bold">' + dkimIcon + ' DKIM</td><td>' + (es.dkim.status || 'unknown') + '</td></tr>';

                esHtml += '</table></div></div>';
                document.getElementById('emailSecurityPane').innerHTML = esHtml;
            }

            // SSL/TLS info (Issue #19)
            if (data.ssl) {
                document.getElementById('resultTabs').style.display = '';
                var ssl = data.ssl;
                var sslHtml = '<div class="card"><div class="card-header"><strong>SSL/TLS Certificate</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                var expiredClass = ssl.expired ? ' class="table-danger"' : '';
                sslHtml += '<tr><td class="fw-bold">Subject</td><td>' + (ssl.subject || '') + '</td></tr>';
                sslHtml += '<tr><td class="fw-bold">Issuer</td><td>' + (ssl.issuer || '') + '</td></tr>';
                sslHtml += '<tr><td class="fw-bold">Valid From</td><td>' + (ssl.valid_from || '') + '</td></tr>';
                sslHtml += '<tr><td class="fw-bold">Valid To</td><td>' + (ssl.valid_to || '') + '</td></tr>';
                sslHtml += '<tr' + expiredClass + '><td class="fw-bold">Expires In</td><td>' + (ssl.expires_in || '') + (ssl.expired ? ' <span class="badge bg-danger">EXPIRED</span>' : '') + '</td></tr>';
                if (ssl.san && ssl.san.length) {
                    sslHtml += '<tr><td class="fw-bold">Alt Names</td><td>' + ssl.san.join(', ') + '</td></tr>';
                }
                sslHtml += '</table></div></div>';
                document.getElementById('sslPane').innerHTML = sslHtml;
            }

            // Wayback Machine link (Issue #54)
            var waybackBtn = document.getElementById('waybackBtn');
            if (waybackBtn) {
                waybackBtn.href = 'https://web.archive.org/web/*/' + encodeURIComponent(currentDomain);
            }

            // Action buttons
            document.getElementById('actionButtons').style.cssText = '';
            isRawView = false;
            updateToggleBtn();
        }

        // ── Result tabs ──
        document.querySelectorAll('#resultTabs .nav-link').forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelectorAll('#resultTabs .nav-link').forEach(function (t) { t.classList.remove('active'); });
                this.classList.add('active');
                var t = this.dataset.tab;
                document.getElementById('whoisResultPane').style.display = t === 'whois' ? '' : 'none';
                document.getElementById('dnsResultPane').style.display = t === 'dns' ? '' : 'none';
                document.getElementById('emailSecurityPane').style.display = t === 'email' ? '' : 'none';
                document.getElementById('sslPane').style.display = t === 'ssl' ? '' : 'none';
            });
        });

        // ── Format WHOIS ──
        function formatWhoisData(html) {
            formattedResult = html.split('\n').map(function (line) {
                var i = line.indexOf(':');
                if (i !== -1) {
                    return '<span class="whois-label">' + line.substring(0, i + 1) + '</span><div class="whois-value">' + line.substring(i + 1).trim() + '</div>';
                }
                return '<span class="whois-value">' + line + '</span>';
            }).join('');
            document.getElementById('result').innerHTML = formattedResult;
        }

        // ── Toggle raw/formatted ──
        document.getElementById('toggleViewBtn').addEventListener('click', function () {
            isRawView = !isRawView;
            document.getElementById('result').innerHTML = isRawView ? '<pre>' + rawWhoisText + '</pre>' : formattedResult;
            updateToggleBtn();
        });
        function updateToggleBtn() { document.getElementById('toggleViewBtn').textContent = isRawView ? 'Show Formatted Whois' : 'Show Raw Whois'; }

        // ── Copy / Download ──
        document.getElementById('copyBtn').addEventListener('click', function () {
            navigator.clipboard.writeText(rawWhoisText.replace(/<[^>]*>/g, '')).then(function () {
                var b = document.getElementById('copyBtn');
                b.innerHTML = '<i class="bi bi-check"></i> Copied!';
                setTimeout(function () { b.innerHTML = '<i class="bi bi-clipboard"></i> Copy'; }, 2000);
            });
        });
        document.getElementById('downloadBtn').addEventListener('click', function () {
            var a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([rawWhoisText.replace(/<[^>]*>/g, '')], { type: 'text/plain' }));
            a.download = currentDomain + '-whois.txt';
            a.click();
            URL.revokeObjectURL(a.href);
        });

        // ── QR code (Issue #50) ──
        document.getElementById('qrCodeBtn').addEventListener('click', function () {
            var shareUrl = window.location.origin + window.location.pathname + '?domain=' + encodeURIComponent(currentDomain);
            var qrApiUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(shareUrl);
            document.getElementById('qrCodeImg').src = qrApiUrl;
            document.getElementById('qrCodeUrl').textContent = shareUrl;
            var modal = new bootstrap.Modal(document.getElementById('qrCodeModal'));
            modal.show();
        });

        // ── Click-to-select WHOIS output (Issue #34) ──
        document.getElementById('result').addEventListener('click', function () {
            var range = document.createRange();
            range.selectNodeContents(this);
            var sel = window.getSelection();
            sel.removeAllRanges();
            sel.addRange(range);

            // Brief highlight flash
            this.classList.add('whois-selected');
            setTimeout(function () {
                document.getElementById('result').classList.remove('whois-selected');
            }, 600);
        });

        // ── Helpers ──
        var defaultTitle = document.title;

        function showLoading(on) {
            document.getElementById('loadingSpinner').style.display = on ? '' : 'none';
            document.getElementById('emptyState').style.display = 'none';
        }

        function hideResults() {
            ['availabilityBadge', 'dataSourceBadge', 'parsedFields', 'resultTabs', 'dnsResultPane', 'emailSecurityPane', 'sslPane', 'bulkResults', 'bulkExportButtons'].forEach(function (id) {
                document.getElementById(id).style.display = 'none';
            });
            document.getElementById('whoisResultPane').style.display = '';
            document.getElementById('result').innerHTML = '';
            document.getElementById('actionButtons').style.cssText = 'display:none !important';
            document.getElementById('emptyState').style.display = 'none';
        }

        function showError(msg) {
            document.getElementById('result').innerHTML = '<div class="alert alert-danger fade-in"><i class="bi bi-exclamation-triangle-fill me-2"></i>' + esc(msg) + '</div>';
        }

        function updateURL(d) {
            history.pushState({ domain: d }, '', window.location.pathname + '?domain=' + encodeURIComponent(d));
            document.title = d + ' — ' + defaultTitle;
        }

        // ── Browser back/forward navigation (Issue #36) ──
        window.addEventListener('popstate', function (e) {
            var params = new URLSearchParams(window.location.search);
            var domain = params.get('domain');
            if (domain) {
                document.getElementById('domain').value = domain;
                triggerLookup(domain);
            } else {
                // Returned to initial state — reset
                document.title = defaultTitle;
                hideResults();
                document.getElementById('emptyState').style.display = '';
                document.getElementById('domain').value = '';
            }
        });
    });
    </script>
</body>
</html>

