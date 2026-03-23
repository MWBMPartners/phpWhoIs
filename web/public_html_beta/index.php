<?php
/**
 * mwWhoIs - Domain WHOIS/RDAP Lookup Tool
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ─── Session & CSRF ───
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'session_config.php';
$csrfToken = $_SESSION['csrf_token'];

// ─── Security headers ───
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");

// ─── Config ───
$config = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php';
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
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
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
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link rel="icon" type="image/png" sizes="512x512" href="assets/images/favicon.png">
    <link rel="icon" type="image/x-icon" href="assets/images/favicon.ico">
    <link rel="icon" type="image/gif" href="assets/images/favicon.gif">
    <link rel="apple-touch-icon" href="assets/images/favicon.png">
    <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo filemtime(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
</head>
<body>
    <!-- Skip to content -->
    <a href="#resultContainer" class="visually-hidden-focusable skip-link">Skip to results</a>

    <!-- Header -->
    <header class="header-form" role="banner">
        <div class="position-relative text-center mb-2">
            <h1 class="mb-0"><a href="/"><img src="assets/images/logo-notext.svg" alt="" style="height: 40px; vertical-align: middle;" aria-hidden="true"><?php if(isset($app["Application"]["Name"]) && $app["Application"]["Name"]){ echo $app["Application"]["Name"];}else{ echo "Whois Lookup";}if(isset($app["Application"]["Version"]["Development"]["Status"]) && $app["Application"]["Version"]["Development"]["Status"]){echo " <span style=\"font-size: 0.7em\">(".$app["Application"]["Version"]["Development"]["Status"].")</span>";} ?></a></h1>
            <div class="d-flex gap-1 position-absolute top-50 end-0 translate-middle-y">
                <!-- Language selector (Issue #59) -->
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="langToggle" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Language" title="Language">
                        <i class="bi bi-translate"></i>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="langToggle">
                        <li><a class="dropdown-item" href="#" data-lang="en">English</a></li>
                        <li><a class="dropdown-item" href="#" data-lang="es">Espa&ntilde;ol</a></li>
                        <li><a class="dropdown-item" href="#" data-lang="fr">Fran&ccedil;ais</a></li>
                        <li><a class="dropdown-item" href="#" data-lang="de">Deutsch</a></li>
                    </ul>
                </div>
                <!-- Theme selector -->
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="themeToggle" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Change theme" title="Change theme">
                        <i class="bi bi-sun-fill" id="themeIcon"></i>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="themeToggle">
                        <li><a class="dropdown-item" href="#" data-theme-value="auto"><i class="bi bi-circle-half me-2"></i><span data-i18n="theme_auto">Auto</span></a></li>
                        <li><a class="dropdown-item" href="#" data-theme-value="light"><i class="bi bi-sun-fill me-2"></i><span data-i18n="theme_light">Light</span></a></li>
                        <li><a class="dropdown-item" href="#" data-theme-value="dark"><i class="bi bi-moon-fill me-2"></i><span data-i18n="theme_dark">Dark</span></a></li>
                        <li><a class="dropdown-item" href="#" data-theme-value="colourblind"><i class="bi bi-eye-fill me-2"></i><span data-i18n="theme_colourblind">Colourblind</span></a></li>
                    </ul>
                </div>
            </div>
        </div>

        <!-- Lookup mode tabs -->
        <ul class="nav nav-tabs mb-3" id="lookupModeTabs" role="tablist">
            <li class="nav-item" role="presentation"><a class="nav-link active" href="#" data-mode="single" role="tab" aria-selected="true" id="tab-single" aria-controls="whoisForm"><span data-i18n="single_lookup">Single Lookup</span></a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-mode="bulk" role="tab" aria-selected="false" id="tab-bulk" aria-controls="bulkWhoisForm"><span data-i18n="bulk_lookup">Bulk Lookup</span></a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-mode="compare" role="tab" aria-selected="false" id="tab-compare" aria-controls="compareForm"><span data-i18n="compare">Compare</span></a></li>
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

        <!-- Compare form (Issue #48) -->
        <form id="compareForm" class="form-container" style="display:none;">
            <div class="form-group flex-grow-1">
                <label for="compareDomain1" class="visually-hidden">First domain</label>
                <input type="text" class="form-control" id="compareDomain1" placeholder="domain1.com" required autocomplete="off">
            </div>
            <span class="align-self-center fw-bold">vs</span>
            <div class="form-group flex-grow-1">
                <label for="compareDomain2" class="visually-hidden">Second domain</label>
                <input type="text" class="form-control" id="compareDomain2" placeholder="domain2.com" required autocomplete="off">
            </div>
            <button type="submit" class="btn btn-primary submit-btn">Compare</button>
        </form>

        <!-- Recent lookups -->
        <div id="historyContainer" class="mt-2" style="display:none;">
            <div class="d-flex align-items-center gap-2">
                <small class="text-muted">Recent:</small>
                <div id="historyList" class="d-flex flex-wrap gap-1"></div>
                <button class="btn btn-sm btn-link text-muted p-0" id="clearHistory" title="Clear history" aria-label="Clear lookup history">
                    <i class="bi bi-x-circle" aria-hidden="true"></i>
                </button>
            </div>
        </div>
    </header>

    <!-- Results section -->
    <main class="result-container" id="resultContainer" role="main">
        <!-- Empty state -->
        <div id="emptyState" class="text-center py-5">
            <i class="bi bi-search" style="font-size: 3rem; opacity: 0.15;"></i>
            <p class="mt-3 text-muted" data-i18n="empty_state">Enter a domain above to get started</p>
        </div>

        <div id="loadingSpinner" class="text-center py-5" role="status" aria-live="polite" style="display:none;">
            <div class="spinner-border text-primary" aria-hidden="true"></div>
            <p class="mt-2 text-muted" data-i18n="loading">Looking up domain information...</p>
        </div>

        <div id="availabilityBadge" class="mb-3" aria-live="polite" aria-atomic="true" style="display:none;"></div>
        <div id="dataSourceBadge" class="mb-2" aria-live="polite" style="display:none;"></div>
        <div id="parsedFields" class="mb-3" style="display:none;"></div>

        <ul class="nav nav-pills mb-3" id="resultTabs" role="tablist" style="display:none;">
            <li class="nav-item" role="presentation"><a class="nav-link active" href="#" data-tab="whois" role="tab" aria-selected="true" id="rtab-whois" aria-controls="whoisResultPane">WHOIS</a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-tab="dns" role="tab" aria-selected="false" id="rtab-dns" aria-controls="dnsResultPane">DNS Records</a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-tab="email" role="tab" aria-selected="false" id="rtab-email" aria-controls="emailSecurityPane">Email Security</a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-tab="ssl" role="tab" aria-selected="false" id="rtab-ssl" aria-controls="sslPane">SSL/TLS</a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-tab="subdomains" role="tab" aria-selected="false" id="rtab-subdomains" aria-controls="subdomainsPane">Subdomains</a></li>
        </ul>

        <div id="whoisResultPane" role="tabpanel" aria-labelledby="rtab-whois"><div id="result"></div></div>
        <div id="dnsResultPane" role="tabpanel" aria-labelledby="rtab-dns" style="display:none;"></div>
        <div id="emailSecurityPane" role="tabpanel" aria-labelledby="rtab-email" style="display:none;"></div>
        <div id="sslPane" role="tabpanel" aria-labelledby="rtab-ssl" style="display:none;"></div>
        <div id="subdomainsPane" role="tabpanel" aria-labelledby="rtab-subdomains" style="display:none;"></div>

        <div id="actionButtons" class="mt-2 d-flex gap-2 flex-wrap" style="display:none !important;">
            <button class="btn btn-secondary btn-sm" id="toggleViewBtn">Show Raw Whois</button>
            <button class="btn btn-outline-secondary btn-sm" id="copyBtn" aria-label="Copy WHOIS data to clipboard"><i class="bi bi-clipboard" aria-hidden="true"></i> Copy</button>
            <button class="btn btn-outline-secondary btn-sm" id="downloadBtn" aria-label="Download WHOIS data as text file"><i class="bi bi-download" aria-hidden="true"></i> Download</button>
            <a href="#" target="_blank" rel="noopener noreferrer" class="btn btn-outline-secondary btn-sm" id="waybackBtn" aria-label="View on Wayback Machine"><i class="bi bi-clock-history" aria-hidden="true"></i> Wayback Machine</a>
            <button class="btn btn-outline-secondary btn-sm" id="qrCodeBtn" aria-label="Generate QR code for sharing"><i class="bi bi-qr-code" aria-hidden="true"></i> QR Code</button>
        </div>

        <!-- QR Code modal (Issue #50) -->
        <div id="qrCodeModal" class="modal fade" tabindex="-1" aria-labelledby="qrCodeModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-sm modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="qrCodeModalLabel">Share Lookup</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body text-center">
                        <img id="qrCodeImg" src="" alt="QR Code" style="max-width:100%;">
                        <p class="small text-muted mt-2" id="qrCodeUrl"></p>
                    </div>
                </div>
            </div>
        </div>

        <div id="bulkProgress" class="mt-3" style="display:none;">
            <div class="d-flex justify-content-between small text-muted mb-1">
                <span id="bulkProgressText">Looking up 0 of 0...</span>
                <span id="bulkProgressPercent">0%</span>
            </div>
            <div class="progress" style="height: 6px;">
                <div class="progress-bar" id="bulkProgressBar" role="progressbar" style="width: 0%;" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100"></div>
            </div>
        </div>
        <div id="bulkResults" class="accordion mt-3" style="display:none;"></div>
        <div id="compareResults" class="mt-3" style="display:none;"></div>

        <!-- Bulk export buttons (Issue #49) -->
        <div id="bulkExportButtons" class="mt-2 gap-2" style="display:none;">
            <button class="btn btn-outline-secondary btn-sm" id="exportCsvBtn" aria-label="Export bulk results as CSV"><i class="bi bi-filetype-csv" aria-hidden="true"></i> Export CSV</button>
            <button class="btn btn-outline-secondary btn-sm" id="exportJsonBtn" aria-label="Export bulk results as JSON"><i class="bi bi-filetype-json" aria-hidden="true"></i> Export JSON</button>
        </div>
    </main>

    <!-- Footer -->
    <footer class="footer" role="contentinfo">
        <div class="footer-row">
            <div class="footer-left">
                Privacy Policy | Terms of Use
            </div>
            <div class="footer-right">
                <?php
                    echo $pageTitle;
                    
                    if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]){
                        echo " v" . htmlspecialchars($app["Application"]["Version"]["Number"]);

                        if (!empty($app["Application"]["Version"]["Repo"]["Commit"]["SHA"]["Short"])){
                            echo ' (<a href="' . htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["URL"]) . '" target="_blank" rel="noopener noreferrer" class="footer-commit">';
                            echo htmlspecialchars($app["Application"]["Version"]["Repo"]["Commit"]["SHA"]["Short"]);
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
    </footer>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var CSRF = '<?php echo htmlspecialchars($csrfToken); ?>';
        var REG_CONFIG = <?php echo json_encode(isset($config['registration']) ? $config['registration'] : ['enabled' => false]); ?>;
        var AFFILIATE_REGISTRARS = <?php echo json_encode(isset($config['affiliate_registrars']) ? $config['affiliate_registrars'] : []); ?>;
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

        // ── i18n (Issue #59) ──
        var i18nStrings = {};
        var currentLang = localStorage.getItem('lang') || navigator.language.split('-')[0] || 'en';

        function loadLanguage(lang) {
            fetch('lang/' + lang + '.json?v=' + Date.now())
                .then(function (r) { if (!r.ok) throw new Error(); return r.json(); })
                .then(function (data) {
                    i18nStrings = data;
                    applyTranslations();
                    document.querySelectorAll('[data-lang]').forEach(function (el) {
                        el.classList.toggle('active', el.dataset.lang === lang);
                    });
                    document.documentElement.setAttribute('lang', lang);
                })
                .catch(function () {
                    // Fallback to English if language not found
                    if (lang !== 'en') loadLanguage('en');
                });
        }

        function t(key) { return i18nStrings[key] || key; }

        function applyTranslations() {
            document.querySelectorAll('[data-i18n]').forEach(function (el) {
                var key = el.dataset.i18n;
                if (i18nStrings[key]) el.textContent = i18nStrings[key];
            });
            document.querySelectorAll('[data-i18n-placeholder]').forEach(function (el) {
                var key = el.dataset.i18nPlaceholder;
                if (i18nStrings[key]) el.placeholder = i18nStrings[key];
            });
        }

        document.querySelectorAll('[data-lang]').forEach(function (item) {
            item.addEventListener('click', function (e) {
                e.preventDefault();
                currentLang = this.dataset.lang;
                localStorage.setItem('lang', currentLang);
                loadLanguage(currentLang);
            });
        });

        // Load initial language
        loadLanguage(currentLang);

        // ── Theme selector (Auto / Light / Dark / Colourblind) ──
        var themeIcon = document.getElementById('themeIcon');
        var theme = localStorage.getItem('theme') || 'auto';
        var systemDarkMQ = window.matchMedia('(prefers-color-scheme: dark)');
        applyTheme(theme);

        // Listen for system theme changes (only affects 'auto' mode)
        systemDarkMQ.addEventListener('change', function () {
            if (theme === 'auto') applyTheme('auto');
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

        // ── Lookup mode tabs ──
        document.querySelectorAll('#lookupModeTabs .nav-link').forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelectorAll('#lookupModeTabs .nav-link').forEach(function (t) { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
                this.classList.add('active');
                this.setAttribute('aria-selected', 'true');
                var mode = this.dataset.mode;
                document.getElementById('whoisForm').style.display = mode === 'single' ? '' : 'none';
                document.getElementById('bulkWhoisForm').style.display = mode === 'bulk' ? '' : 'none';
                document.getElementById('compareForm').style.display = mode === 'compare' ? '' : 'none';
            });
        });

        // ── History ──
        function getHistory() { try { return JSON.parse(localStorage.getItem('whoisHistory') || '[]'); } catch (e) { return []; } }
        function getTimeline() { try { return JSON.parse(localStorage.getItem('whoisTimeline') || '{}'); } catch (e) { return {}; } }
        function saveToHistory(domain, data) {
            var h = getHistory().filter(function (x) { return x.domain !== domain; });
            h.unshift({ domain: domain, ts: Date.now() });
            if (h.length > 10) h = h.slice(0, 10);
            localStorage.setItem('whoisHistory', JSON.stringify(h));
            renderHistory();

            // Save timeline snapshot (Issue #47)
            if (data && data.parsed && Object.keys(data.parsed).length) {
                var timeline = getTimeline();
                if (!timeline[domain]) timeline[domain] = [];
                var snapshot = { ts: Date.now(), parsed: data.parsed, availability: data.availability, data_source: data.data_source };
                // Only save if different from last snapshot
                var last = timeline[domain].length ? timeline[domain][timeline[domain].length - 1] : null;
                if (!last || JSON.stringify(last.parsed) !== JSON.stringify(snapshot.parsed)) {
                    timeline[domain].push(snapshot);
                    // Keep last 20 snapshots per domain
                    if (timeline[domain].length > 20) timeline[domain] = timeline[domain].slice(-20);
                    localStorage.setItem('whoisTimeline', JSON.stringify(timeline));
                }
            }
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

        // ── Compare form submit (Issue #48) ──
        document.getElementById('compareForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var d1 = document.getElementById('compareDomain1').value.trim();
            var d2 = document.getElementById('compareDomain2').value.trim();
            if (d1 && d2) triggerCompare(d1, d2);
        });

        function triggerCompare(domain1, domain2) {
            showLoading(true);
            hideResults();
            var results = {};
            var done = 0;

            [domain1, domain2].forEach(function (domain) {
                var fd = new FormData();
                fd.append('domain', domain);
                fd.append('csrf_token', CSRF);

                fetch('lookup.php?nocache=' + Date.now(), { method: 'POST', body: fd })
                    .then(function (r) { return r.json(); })
                    .then(function (data) { results[domain] = data; })
                    .catch(function () { results[domain] = { error: 'Lookup failed' }; })
                    .finally(function () {
                        if (++done === 2) {
                            showLoading(false);
                            displayCompare(domain1, domain2, results[domain1], results[domain2]);
                        }
                    });
            });
        }

        function displayCompare(d1, d2, data1, data2) {
            var cr = document.getElementById('compareResults');
            var html = '<h5 class="mb-3"><i class="bi bi-arrow-left-right me-2" aria-hidden="true"></i>Domain Comparison</h5>';
            html += '<div class="table-responsive"><table class="table table-bordered table-sm"><thead><tr><th>Field</th><th>' + esc(d1) + '</th><th>' + esc(d2) + '</th></tr></thead><tbody>';

            var fields = ['availability', 'data_source'];
            var parsedKeys = {};
            if (data1.parsed) for (var k in data1.parsed) parsedKeys[k] = true;
            if (data2.parsed) for (var k in data2.parsed) parsedKeys[k] = true;

            // Availability row
            html += '<tr><td class="fw-bold">Availability</td><td>' + esc(data1.availability || 'N/A') + '</td><td>' + esc(data2.availability || 'N/A') + '</td></tr>';
            html += '<tr><td class="fw-bold">Data Source</td><td>' + esc(data1.data_source || 'N/A') + '</td><td>' + esc(data2.data_source || 'N/A') + '</td></tr>';

            // Parsed fields
            for (var key in parsedKeys) {
                var v1 = data1.parsed && data1.parsed[key] ? (Array.isArray(data1.parsed[key]) ? data1.parsed[key].join(', ') : data1.parsed[key]) : '';
                var v2 = data2.parsed && data2.parsed[key] ? (Array.isArray(data2.parsed[key]) ? data2.parsed[key].join(', ') : data2.parsed[key]) : '';
                var diffClass = v1 !== v2 ? ' class="table-warning"' : '';
                html += '<tr' + diffClass + '><td class="fw-bold">' + esc(key) + '</td><td>' + esc(v1 || '-') + '</td><td>' + esc(v2 || '-') + '</td></tr>';
            }

            // DNS counts
            var dns1 = data1.dns ? data1.dns.length : 0;
            var dns2 = data2.dns ? data2.dns.length : 0;
            html += '<tr><td class="fw-bold">DNS Records</td><td>' + dns1 + ' records</td><td>' + dns2 + ' records</td></tr>';

            // SSL
            if (data1.ssl || data2.ssl) {
                var ssl1 = data1.ssl || {};
                var ssl2 = data2.ssl || {};
                html += '<tr><td class="fw-bold">SSL Issuer</td><td>' + esc(ssl1.issuer || 'N/A') + '</td><td>' + esc(ssl2.issuer || 'N/A') + '</td></tr>';
                html += '<tr><td class="fw-bold">SSL Expires</td><td>' + esc(ssl1.expires_in || 'N/A') + '</td><td>' + esc(ssl2.expires_in || 'N/A') + '</td></tr>';
            }

            html += '</tbody></table></div>';
            cr.innerHTML = html;
            cr.style.display = '';
        }

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
                    saveToHistory(domain, data);
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
            var total = domains.length;

            // Show progress bar
            var progressEl = document.getElementById('bulkProgress');
            var progressBar = document.getElementById('bulkProgressBar');
            var progressText = document.getElementById('bulkProgressText');
            var progressPercent = document.getElementById('bulkProgressPercent');
            progressEl.style.display = '';
            progressBar.style.width = '0%';
            progressText.textContent = 'Looking up 0 of ' + total + '...';
            progressPercent.textContent = '0%';

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
                        .catch(function (err) {
                            var item = document.createElement('div');
                            item.className = 'accordion-item';
                            item.innerHTML =
                                '<h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#bulk-' + i + '">' +
                                esc(domain) + ' <span class="badge bg-danger ms-2">Error</span>' +
                                '</button></h2>' +
                                '<div id="bulk-' + i + '" class="accordion-collapse collapse"><div class="accordion-body"><div class="alert alert-danger mb-0"><i class="bi bi-exclamation-triangle-fill me-2"></i>' +
                                esc(err.message || 'Lookup failed') + '</div></div></div>';
                            acc.appendChild(item);
                        })
                        .finally(function () {
                            ++done;
                            var pct = Math.round((done / total) * 100);
                            progressBar.style.width = pct + '%';
                            progressBar.setAttribute('aria-valuenow', pct);
                            progressText.textContent = 'Looking up ' + done + ' of ' + total + '...';
                            progressPercent.textContent = pct + '%';
                            if (done === total) {
                                showLoading(false);
                                progressText.textContent = 'Complete — ' + total + ' domains looked up';
                                progressBar.classList.add('bg-success');
                                if (bulkResultsData.length > 0) {
                                    document.getElementById('bulkExportButtons').style.display = 'flex';
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
                var regButtons = '';
                if (REG_CONFIG.enabled) {
                    var regUrl = REG_CONFIG.url_template.replace('{domain}', encodeURIComponent(currentDomain));
                    var regTarget = REG_CONFIG.open_in_new_tab ? ' target="_blank" rel="noopener noreferrer"' : '';
                    regButtons = '<a href="' + regUrl + '"' + regTarget + ' class="btn btn-success btn-sm"><i class="bi bi-cart-plus me-1" aria-hidden="true"></i>' + REG_CONFIG.button_text + '</a>';
                }
                // Affiliate registrars (Issue #63)
                if (AFFILIATE_REGISTRARS.length) {
                    AFFILIATE_REGISTRARS.forEach(function (aff) {
                        var affUrl = aff.url_template.replace('{domain}', encodeURIComponent(currentDomain));
                        var affTarget = aff.open_in_new_tab ? ' target="_blank" rel="noopener noreferrer"' : '';
                        regButtons += ' <a href="' + affUrl + '"' + affTarget + ' class="btn btn-outline-success btn-sm"><i class="bi bi-box-arrow-up-right me-1" aria-hidden="true"></i>' + esc(aff.name) + '</a>';
                    });
                }
                avBadge.innerHTML = '<div class="alert alert-success d-flex align-items-center justify-content-between flex-wrap gap-2">' +
                    '<div><i class="bi bi-check-circle-fill me-2"></i><strong>' + esc(currentDomain) + '</strong> appears to be available!</div>' +
                    '<div class="d-flex gap-1 flex-wrap">' + regButtons + '</div></div>';
            } else {
                avBadge.innerHTML = '<div class="alert alert-info d-flex align-items-center"><i class="bi bi-info-circle-fill me-2"></i><strong>' + esc(currentDomain) + '</strong>&nbsp;is registered.</div>';
            }
            avBadge.style.display = '';

            // Screenshot preview (Issue #55)
            if (data.screenshot_url && data.availability === 'registered') {
                avBadge.innerHTML += '<div class="card mt-2"><div class="card-body p-2 text-center"><img src="' + data.screenshot_url + '" alt="Website preview of ' + esc(currentDomain) + '" class="img-fluid rounded" style="max-height:300px;" loading="lazy" onerror="this.parentElement.parentElement.style.display=\'none\'"></div></div>';
            }

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
                html += '</table>';
                // Safe Browsing warning (Issue #52)
                if (data.safe_browsing && !data.safe_browsing.safe) {
                    html += '<div class="alert alert-danger mt-2 mb-0 small"><i class="bi bi-shield-exclamation me-1" aria-hidden="true"></i><strong>Security Warning:</strong> This domain is flagged by Google Safe Browsing — ' + esc(data.safe_browsing.threats.join(', ')) + '</div>';
                }

                // VirusTotal reputation (Issue #53)
                if (data.virustotal) {
                    var vt = data.virustotal;
                    var vtClass = vt.malicious > 0 ? 'alert-danger' : (vt.suspicious > 0 ? 'alert-warning' : 'alert-info');
                    var vtIcon = vt.malicious > 0 ? 'bi-shield-x' : (vt.suspicious > 0 ? 'bi-shield-exclamation' : 'bi-shield-check');
                    html += '<div class="alert ' + vtClass + ' mt-2 mb-0 small"><i class="bi ' + vtIcon + ' me-1" aria-hidden="true"></i><strong>VirusTotal:</strong> ' + vt.malicious + ' malicious, ' + vt.suspicious + ' suspicious, ' + vt.harmless + ' clean detections</div>';
                }

                // Registrar reputation flag (Issue #51)
                if (data.registrar_reputation) {
                    var repClass = data.registrar_reputation.rating === 'warning' ? 'alert-danger' : 'alert-warning';
                    var repIcon = data.registrar_reputation.rating === 'warning' ? 'bi-exclamation-triangle-fill' : 'bi-exclamation-circle-fill';
                    html += '<div class="alert ' + repClass + ' mt-2 mb-0 small"><i class="bi ' + repIcon + ' me-1" aria-hidden="true"></i><strong>Registrar Notice:</strong> ' + esc(data.registrar_reputation.reason) + '</div>';
                }
                html += '</div></div>';
                pf.innerHTML = html;
                pf.style.display = '';
            }

            // IP geolocation (Issue #18)
            if (data.geolocation) {
                var geo = data.geolocation;
                var geoHtml = '<div class="card mt-3"><div class="card-header"><strong>Server Location</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                if (geo.city) { geoHtml += '<tr><td class="fw-bold">City</td><td>' + esc(geo.city) + '</td></tr>'; }
                if (geo.country) { geoHtml += '<tr><td class="fw-bold">Country</td><td>' + esc(geo.country) + ' (' + esc(geo.country_code) + ')</td></tr>'; }
                if (geo.isp) { geoHtml += '<tr><td class="fw-bold">ISP</td><td>' + esc(geo.isp) + '</td></tr>'; }
                if (geo.org) { geoHtml += '<tr><td class="fw-bold">Organization</td><td>' + esc(geo.org) + '</td></tr>'; }
                if (geo.as) { geoHtml += '<tr><td class="fw-bold">AS</td><td>' + esc(geo.as) + '</td></tr>'; }
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
                    dnsHtml += '<tr><td><span class="badge bg-secondary">' + esc(r.type) + '</span></td><td>' + esc(r.value) + '</td><td>' + esc(r.priority || '') + '</td></tr>';
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

                // HIBP breach data (Issue #65)
                if (data.hibp && data.hibp.length > 0) {
                    esHtml += '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-shield-exclamation me-1" aria-hidden="true"></i>Data Breaches</strong> <span class="badge bg-danger">' + data.hibp.length + '</span></div><div class="card-body"><table class="table table-sm mb-0"><thead><tr><th>Breach</th><th>Date</th><th>Accounts</th><th>Compromised Data</th></tr></thead><tbody>';
                    data.hibp.forEach(function (b) {
                        esHtml += '<tr><td class="fw-bold">' + esc(b.title) + '</td><td>' + esc(b.date) + '</td><td>' + (b.pwn_count ? b.pwn_count.toLocaleString() : 'N/A') + '</td><td><small>' + esc(b.data_classes.join(', ')) + '</small></td></tr>';
                    });
                    esHtml += '</tbody></table></div></div>';
                } else if (data.hibp !== null && data.hibp.length === 0) {
                    esHtml += '<div class="alert alert-success mt-3 small"><i class="bi bi-shield-check me-1" aria-hidden="true"></i>No known data breaches found for this domain.</div>';
                }

                document.getElementById('emailSecurityPane').innerHTML = esHtml;
            }

            // SSL/TLS info (Issue #19)
            if (data.ssl) {
                document.getElementById('resultTabs').style.display = '';
                var ssl = data.ssl;
                var sslHtml = '<div class="card"><div class="card-header"><strong>SSL/TLS Certificate</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                var expiredClass = ssl.expired ? ' class="table-danger"' : '';
                sslHtml += '<tr><td class="fw-bold">Subject</td><td>' + esc(ssl.subject || '') + '</td></tr>';
                sslHtml += '<tr><td class="fw-bold">Issuer</td><td>' + esc(ssl.issuer || '') + '</td></tr>';
                sslHtml += '<tr><td class="fw-bold">Valid From</td><td>' + esc(ssl.valid_from || '') + '</td></tr>';
                sslHtml += '<tr><td class="fw-bold">Valid To</td><td>' + esc(ssl.valid_to || '') + '</td></tr>';
                sslHtml += '<tr' + expiredClass + '><td class="fw-bold">Expires In</td><td>' + esc(ssl.expires_in || '') + (ssl.expired ? ' <span class="badge bg-danger">EXPIRED</span>' : '') + '</td></tr>';
                if (ssl.san && ssl.san.length) {
                    sslHtml += '<tr><td class="fw-bold">Alt Names</td><td>' + ssl.san.map(esc).join(', ') + '</td></tr>';
                }
                sslHtml += '</table></div></div>';
                document.getElementById('sslPane').innerHTML = sslHtml;
            }

            // Subdomains (Issue #46)
            if (data.subdomains && data.subdomains.length) {
                document.getElementById('resultTabs').style.display = '';
                var subHtml = '<div class="card"><div class="card-header"><strong>Discovered Subdomains</strong> <span class="badge bg-secondary">' + data.subdomains.length + ' found</span></div><div class="card-body"><table class="table table-striped table-sm mb-0"><thead><tr><th>Subdomain</th><th>IP Address</th></tr></thead><tbody>';
                data.subdomains.forEach(function (s) {
                    subHtml += '<tr><td>' + esc(s.subdomain) + '</td><td><code>' + esc(s.ip) + '</code></td></tr>';
                });
                subHtml += '</tbody></table></div></div>';
                document.getElementById('subdomainsPane').innerHTML = subHtml;
            }

            // WHOIS history timeline (Issue #47)
            var timeline = getTimeline();
            var domainTimeline = timeline[currentDomain] || [];
            if (domainTimeline.length > 1) {
                var tlHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-clock-history me-1" aria-hidden="true"></i>Change History</strong> <span class="badge bg-secondary">' + domainTimeline.length + ' snapshots</span></div><div class="card-body">';
                tlHtml += '<div class="timeline-list">';
                for (var ti = domainTimeline.length - 1; ti >= 0; ti--) {
                    var snap = domainTimeline[ti];
                    var date = new Date(snap.ts).toLocaleString();
                    tlHtml += '<div class="border-start border-2 ps-3 mb-3 position-relative"><small class="text-muted">' + date + '</small>';
                    if (ti < domainTimeline.length - 1) {
                        var prev = domainTimeline[ti + 1];
                        var changes = [];
                        for (var k in snap.parsed) {
                            var sv = Array.isArray(snap.parsed[k]) ? snap.parsed[k].join(', ') : snap.parsed[k];
                            var pv = prev.parsed[k] ? (Array.isArray(prev.parsed[k]) ? prev.parsed[k].join(', ') : prev.parsed[k]) : '';
                            if (sv !== pv) changes.push('<strong>' + k + ':</strong> ' + esc(pv || '(none)') + ' → ' + esc(sv));
                        }
                        if (changes.length) {
                            tlHtml += '<ul class="mb-0 small">';
                            changes.forEach(function (c) { tlHtml += '<li>' + c + '</li>'; });
                            tlHtml += '</ul>';
                        } else {
                            tlHtml += '<p class="small mb-0 text-muted">No changes detected</p>';
                        }
                    } else {
                        tlHtml += '<p class="small mb-0">Initial snapshot</p>';
                    }
                    tlHtml += '</div>';
                }
                tlHtml += '</div></div></div>';
                document.getElementById('parsedFields').innerHTML += tlHtml;
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
                document.querySelectorAll('#resultTabs .nav-link').forEach(function (t) { t.classList.remove('active'); t.setAttribute('aria-selected', 'false'); });
                this.classList.add('active');
                this.setAttribute('aria-selected', 'true');
                var t = this.dataset.tab;
                document.getElementById('whoisResultPane').style.display = t === 'whois' ? '' : 'none';
                document.getElementById('dnsResultPane').style.display = t === 'dns' ? '' : 'none';
                document.getElementById('emailSecurityPane').style.display = t === 'email' ? '' : 'none';
                document.getElementById('sslPane').style.display = t === 'ssl' ? '' : 'none';
                document.getElementById('subdomainsPane').style.display = t === 'subdomains' ? '' : 'none';
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
            ['availabilityBadge', 'dataSourceBadge', 'parsedFields', 'resultTabs', 'dnsResultPane', 'emailSecurityPane', 'sslPane', 'subdomainsPane', 'bulkResults', 'bulkProgress', 'bulkExportButtons', 'compareResults'].forEach(function (id) {
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

