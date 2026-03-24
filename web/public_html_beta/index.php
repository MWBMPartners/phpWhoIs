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
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; img-src 'self' data: https://image.thum.io https://api.qrserver.com https://*.gstatic.com; connect-src 'self'");

// ─── Config ───
$config = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php')) {
    require_once (__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php');
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
if (isset($app["Application"]["Name"]) && $app["Application"]["Name"]) {
    $poweredBy = $app["Application"]["Name"];
    if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]) {
        $poweredBy .= '/' . $app["Application"]["Version"]["Number"];
    }
    header('X-Powered-By: ' . $poweredBy);
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
    <link rel="alternate" type="application/rss+xml" title="<?php echo htmlspecialchars($pageTitle); ?> — Domain Changes" href="feed">
<?php if (empty($app["Application"]["Version"]["Development"]["Status"])): ?>
    <link rel="manifest" href="manifest.json">
<?php endif; ?>
    <meta name="theme-color" content="#0d6efd">
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "WebApplication",
        "name": "<?php echo htmlspecialchars($pageTitle); ?>",
        "description": "<?php echo htmlspecialchars($pageDescription); ?>",
        "url": "<?php echo htmlspecialchars(strtok($pageUrl, '?')); ?>",
        "applicationCategory": "UtilityApplication",
        "operatingSystem": "Any",
        "offers": { "@type": "Offer", "price": "0", "priceCurrency": "GBP" }
    }
    </script>
    <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo filemtime(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
</head>
<body>
    <!-- Skip links -->
    <a href="#domain" class="visually-hidden-focusable skip-link">Skip to search</a>
    <a href="#resultContainer" class="visually-hidden-focusable skip-link">Skip to results</a>

    <noscript>
        <div class="alert alert-warning text-center m-3">This tool requires JavaScript to perform WHOIS lookups. Please enable JavaScript in your browser settings.</div>
    </noscript>

    <?php if (empty($app["Application"]["Version"]["Development"]["Status"])): ?>
    <!-- PWA install banner — production only (Issue #170) -->
    <div id="pwaInstallBanner" class="alert alert-primary d-flex align-items-center gap-2 m-0 py-2 px-3 rounded-0 small" style="display:none;" role="alert">
        <i class="bi bi-download" aria-hidden="true"></i>
        <span>Install <strong><?php echo htmlspecialchars($pageTitle); ?></strong> for quick access</span>
        <div class="ms-auto d-flex align-items-center gap-2 flex-shrink-0">
            <button class="btn btn-primary btn-sm" id="pwaInstallBtn">Install</button>
            <button type="button" class="btn-close" id="pwaInstallDismiss" aria-label="Dismiss"></button>
        </div>
    </div>
    <?php endif; ?>

    <!-- Header -->
    <header class="header-form">
        <div class="position-relative text-center mb-2">
            <h1 class="mb-0"><a href="/"><img src="assets/images/logo-notext.svg" alt="" style="height: 40px; vertical-align: middle;" aria-hidden="true"><?php if(isset($app["Application"]["Name"]) && $app["Application"]["Name"]){ echo $app["Application"]["Name"];}else{ echo "Whois Lookup";}if(isset($app["Application"]["Version"]["Development"]["Status"]) && $app["Application"]["Version"]["Development"]["Status"]){echo " <span style=\"font-size: 0.7em\">(".$app["Application"]["Version"]["Development"]["Status"].")</span>";} ?></a></h1>
            <div class="d-flex gap-1 position-absolute top-50 end-0 translate-middle-y">
                <!-- Language selector (Issue #59) -->
                <div class="dropdown">
                    <button class="btn btn-sm btn-outline-secondary dropdown-toggle" type="button" id="langToggle" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Language" title="Language">
                        <i class="bi bi-translate"></i>
                    </button>
                    <ul class="dropdown-menu dropdown-menu-end" aria-labelledby="langToggle" role="menu">
                        <li><button class="dropdown-item" type="button" data-lang="en" role="menuitem">English</button></li>
                        <li><button class="dropdown-item" type="button" data-lang="es" role="menuitem">Espa&ntilde;ol</button></li>
                        <li><button class="dropdown-item" type="button" data-lang="fr" role="menuitem">Fran&ccedil;ais</button></li>
                        <li><button class="dropdown-item" type="button" data-lang="de" role="menuitem">Deutsch</button></li>
                    </ul>
                </div>
                <!-- Settings button (Issue #181) -->
                <button class="btn btn-sm btn-outline-secondary" type="button" id="settingsBtn" data-bs-toggle="modal" data-bs-target="#settingsModal" aria-label="Settings" title="Settings">
                    <i class="bi bi-gear-fill" id="themeIcon"></i>
                </button>
            </div>
        </div>

        <!-- Lookup mode tabs -->
        <ul class="nav nav-tabs mb-3" id="lookupModeTabs" role="tablist">
            <li class="nav-item" role="presentation"><a class="nav-link active" href="#" data-mode="single" role="tab" aria-selected="true" id="tab-single" aria-controls="singlePanel"><span data-i18n="single_lookup">Single Lookup</span></a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-mode="bulk" role="tab" aria-selected="false" id="tab-bulk" aria-controls="bulkWhoisPanel"><span data-i18n="bulk_lookup">Bulk Lookup</span></a></li>
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-mode="compare" role="tab" aria-selected="false" id="tab-compare" aria-controls="comparePanel"><span data-i18n="compare">Compare</span></a></li>
        </ul>

        <!-- Single domain form -->
        <div role="tabpanel" aria-labelledby="tab-single" id="singlePanel">
        <form id="whoisForm" class="form-container">
            <div class="form-group flex-grow-1">
                <label for="domain" class="visually-hidden">Domain or URL</label>
                <input type="text" class="form-control" id="domain" name="domain"
                    title="Please enter a valid domain name, e.g., example.com"
                    placeholder="example.com" required autocomplete="off"
                    aria-describedby="domainFeedback">
                <div class="invalid-feedback" id="domainFeedback" role="alert"></div>
            </div>
            <button type="submit" class="btn btn-primary submit-btn" id="lookupBtn">Lookup</button>
        </form>
        </div>

        <!-- Bulk domain form -->
        <div role="tabpanel" aria-labelledby="tab-bulk" style="display:none;" id="bulkWhoisPanel">
        <form id="bulkWhoisForm" class="form-container">
            <div class="form-group flex-grow-1">
                <label for="bulkDomains" class="visually-hidden">Domains (one per line)</label>
                <textarea class="form-control" id="bulkDomains" name="domains" rows="4"
                    placeholder="example.com&#10;example.org&#10;example.net" required></textarea>
            </div>
            <div class="d-flex gap-2 align-items-center">
                <button type="submit" class="btn btn-primary submit-btn">Lookup All</button>
                <label class="btn btn-outline-secondary btn-sm mb-0" for="bulkFileInput" title="Import from file"><i class="bi bi-upload me-1"></i>Import</label>
                <input type="file" id="bulkFileInput" accept=".txt,.csv" class="d-none">
            </div>
        </form>
        </div>

        <!-- Compare form (Issue #48) -->
        <div role="tabpanel" aria-labelledby="tab-compare" style="display:none;" id="comparePanel">
        <form id="compareForm" class="form-container">
            <div class="form-group flex-grow-1">
                <label for="compareDomain1" class="visually-hidden">First domain</label>
                <input type="text" class="form-control" id="compareDomain1" placeholder="domain1.com" required autocomplete="off">
            </div>
            <span class="align-self-center fw-bold" aria-hidden="true">vs</span>
            <div class="form-group flex-grow-1">
                <label for="compareDomain2" class="visually-hidden">Second domain</label>
                <input type="text" class="form-control" id="compareDomain2" placeholder="domain2.com" required autocomplete="off">
            </div>
            <button type="submit" class="btn btn-primary submit-btn">Compare</button>
        </form>
        </div>

        <!-- Recent lookups -->
        <div id="historyContainer" class="mt-2" style="display:none;">
            <div class="d-flex align-items-center gap-2">
                <small class="text-muted">Recent:</small>
                <div id="historyList" class="d-flex flex-wrap gap-1"></div>
                <button class="btn btn-sm btn-link text-muted p-0" id="clearHistory" title="Clear history" aria-label="Clear lookup history">
                    <i class="bi bi-x-circle" aria-hidden="true"></i>
                </button>
<?php
// Portfolio icon: requires config enabled + user logged in (Issue #171)
// $_SESSION['logged_in'] set by user account system (Issue #163)
$_showPortfolioIcon = !empty($config['portfolio_enabled']) && !empty($_SESSION['logged_in']);
if ($_showPortfolioIcon): ?>
                <a href="portfolio" class="btn btn-sm btn-link text-muted p-0 ms-1" id="historyPortfolioLink" title="Domain Portfolio" aria-label="Domain Portfolio" style="display:none;">
                    <i class="bi bi-collection" aria-hidden="true"></i>
                </a>
<?php endif; ?>
                <a href="feed-watchlist" class="btn btn-sm btn-link text-muted p-0 ms-1" id="historyWatchlistFeed" title="Watchlist RSS Feed" aria-label="Watchlist RSS Feed" style="display:none;">
                    <i class="bi bi-rss" aria-hidden="true"></i>
                </a>
            </div>
        </div>
    </header>

    <!-- Results section -->
    <main class="result-container" id="resultContainer" aria-live="polite">
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
            <li class="nav-item" role="presentation"><a class="nav-link" href="#" data-tab="security" role="tab" aria-selected="false" id="rtab-security" aria-controls="securityPane">Security</a></li>
        </ul>

        <div id="whoisResultPane" role="tabpanel" aria-labelledby="rtab-whois"><div id="result"></div></div>
        <div id="dnsResultPane" role="tabpanel" aria-labelledby="rtab-dns" style="display:none;"></div>
        <div id="emailSecurityPane" role="tabpanel" aria-labelledby="rtab-email" style="display:none;"></div>
        <div id="sslPane" role="tabpanel" aria-labelledby="rtab-ssl" style="display:none;"></div>
        <div id="subdomainsPane" role="tabpanel" aria-labelledby="rtab-subdomains" style="display:none;"></div>
        <div id="securityPane" role="tabpanel" aria-labelledby="rtab-security" style="display:none;"></div>

        <div id="actionButtons" class="mt-2 d-flex gap-2 flex-wrap" style="display:none !important;">
            <button class="btn btn-secondary btn-sm" id="toggleViewBtn">Show Raw Whois</button>
            <button class="btn btn-outline-secondary btn-sm" id="copyBtn" aria-label="Copy WHOIS data to clipboard"><i class="bi bi-clipboard" aria-hidden="true"></i> Copy</button>
            <button class="btn btn-outline-secondary btn-sm" id="downloadBtn" aria-label="Download WHOIS data as text file"><i class="bi bi-download" aria-hidden="true"></i> Download</button>
            <a href="#" target="_blank" rel="noopener noreferrer" class="btn btn-outline-secondary btn-sm" id="waybackBtn" aria-label="View on Wayback Machine"><i class="bi bi-clock-history" aria-hidden="true"></i> Wayback Machine</a>
            <button class="btn btn-outline-secondary btn-sm" id="qrCodeBtn" aria-label="Generate QR code for sharing"><i class="bi bi-qr-code" aria-hidden="true"></i> QR Code</button>
            <button class="btn btn-outline-secondary btn-sm" id="exportJsonSingleBtn" aria-label="Export lookup as JSON"><i class="bi bi-filetype-json" aria-hidden="true"></i> Export JSON</button>
            <button class="btn btn-outline-info btn-sm" id="diffBtn" aria-label="Compare cached vs fresh WHOIS"><i class="bi bi-arrow-repeat" aria-hidden="true"></i> Refresh &amp; Diff</button>
            <button class="btn btn-outline-secondary btn-sm" id="printPdfBtn" aria-label="Save as PDF"><i class="bi bi-file-pdf" aria-hidden="true"></i> PDF</button>
            <button class="btn btn-outline-secondary btn-sm" id="shareBtn" aria-label="Copy share link"><i class="bi bi-share" aria-hidden="true"></i> Share</button>
        </div>

        <!-- QR Code modal (Issue #50) -->
        <div id="qrCodeModal" class="modal fade" tabindex="-1" role="dialog" aria-labelledby="qrCodeModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-sm modal-dialog-centered">
                <div class="modal-content">
                    <div class="modal-header">
                        <h2 class="modal-title fs-5" id="qrCodeModalLabel">Share Lookup</h2>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body text-center">
                        <img id="qrCodeImg" src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7" alt="QR Code" style="max-width:100%;">
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
            <div class="progress" style="height: 6px;" role="progressbar" aria-label="Bulk lookup progress" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100">
                <div class="progress-bar" id="bulkProgressBar" style="width: 0%;"></div>
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

    <!-- Settings Modal (Issue #181) -->
    <div class="modal fade" id="settingsModal" tabindex="-1" aria-labelledby="settingsModalLabel" aria-hidden="true">
        <div class="modal-dialog">
            <div class="modal-content">
                <div class="modal-header">
                    <h5 class="modal-title" id="settingsModalLabel"><i class="bi bi-gear-fill me-2"></i>Settings</h5>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                </div>
                <div class="modal-body">
                    <!-- Theme -->
                    <h6 class="fw-bold mb-2"><i class="bi bi-palette me-1"></i>Theme</h6>
                    <div class="btn-group w-100 mb-4" role="group" aria-label="Theme selection">
                        <button type="button" class="btn btn-outline-secondary" data-theme-value="auto"><i class="bi bi-circle-half me-1"></i>Auto</button>
                        <button type="button" class="btn btn-outline-secondary" data-theme-value="light"><i class="bi bi-sun-fill me-1"></i>Light</button>
                        <button type="button" class="btn btn-outline-secondary" data-theme-value="dark"><i class="bi bi-moon-fill me-1"></i>Dark</button>
                        <button type="button" class="btn btn-outline-secondary" data-theme-value="colourblind"><i class="bi bi-eye-fill me-1"></i>Colourblind</button>
                    </div>

                    <!-- Default View Mode -->
                    <h6 class="fw-bold mb-2"><i class="bi bi-layout-text-window me-1"></i>Default View Mode</h6>
                    <p class="text-muted small mb-2">These defaults apply when no URL parameters are specified.</p>
                    <div class="form-check form-switch mb-2">
                        <input class="form-check-input" type="checkbox" id="settingHideSecScore">
                        <label class="form-check-label" for="settingHideSecScore">Hide Security Score</label>
                    </div>
                    <div class="form-check form-switch mb-3">
                        <input class="form-check-input" type="checkbox" id="settingHideSummary">
                        <label class="form-check-label" for="settingHideSummary">Hide Domain Summary</label>
                    </div>

                    <label class="form-label fw-bold small" for="settingDefaultTabs">Default Tabs</label>
                    <p class="text-muted small mb-2">Select which tabs to show. Leave all checked for the full view.</p>
                    <div class="row row-cols-2 g-2 mb-3" id="settingDefaultTabs">
                        <div class="col"><div class="form-check"><input class="form-check-input setting-tab-check" type="checkbox" value="whois" id="stWhois" checked><label class="form-check-label" for="stWhois">WHOIS</label></div></div>
                        <div class="col"><div class="form-check"><input class="form-check-input setting-tab-check" type="checkbox" value="dns" id="stDns" checked><label class="form-check-label" for="stDns">DNS Records</label></div></div>
                        <div class="col"><div class="form-check"><input class="form-check-input setting-tab-check" type="checkbox" value="email" id="stEmail" checked><label class="form-check-label" for="stEmail">Email Security</label></div></div>
                        <div class="col"><div class="form-check"><input class="form-check-input setting-tab-check" type="checkbox" value="ssl" id="stSsl" checked><label class="form-check-label" for="stSsl">SSL/TLS</label></div></div>
                        <div class="col"><div class="form-check"><input class="form-check-input setting-tab-check" type="checkbox" value="subdomains" id="stSubs" checked><label class="form-check-label" for="stSubs">Subdomains</label></div></div>
                        <div class="col"><div class="form-check"><input class="form-check-input setting-tab-check" type="checkbox" value="security" id="stSec" checked><label class="form-check-label" for="stSec">Security</label></div></div>
                    </div>

                    <div class="alert alert-info small mb-0">
                        <i class="bi bi-info-circle me-1"></i>
                        Settings are saved in your browser. <span class="text-muted">When user accounts are available, settings will sync to your profile.</span>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-outline-danger btn-sm" id="settingsReset"><i class="bi bi-arrow-counterclockwise me-1"></i>Reset to Defaults</button>
                    <button type="button" class="btn btn-primary" data-bs-dismiss="modal">Done</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Footer -->
    <?php $appName = $pageTitle; require __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'footer.php'; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var CSRF = '<?php echo htmlspecialchars($csrfToken); ?>';
        var browserDnt = navigator.doNotTrack === '1' || window.doNotTrack === '1';
        var REGISTRARS = <?php
            // New format: 'registrars' array — filter to enabled only
            if (!empty($config['registrars'])) {
                $enabled = array_values(array_filter($config['registrars'], function ($r) {
                    return !isset($r['enabled']) || $r['enabled'] === true;
                }));
                echo json_encode($enabled);
            }
            // Legacy fallback: 'registration' + 'affiliate_registrars'
            elseif (!empty($config['registration']['enabled'])) {
                $legacy = [['name' => $config['registration']['button_text'] ?? 'Register', 'url_template' => $config['registration']['url_template'], 'open_in_new_tab' => $config['registration']['open_in_new_tab'] ?? true]];
                if (!empty($config['affiliate_registrars'])) {
                    $legacy = array_merge($legacy, $config['affiliate_registrars']);
                }
                echo json_encode($legacy);
            } else {
                echo '[]';
            }
        ?>;

        // Build registration button(s) — single = direct link, multiple = dropdown
        var fallbackIcon = '<i class="bi bi-box-arrow-up-right me-2" aria-hidden="true"></i>';

        function registrarFavicon(urlTemplate) {
            try {
                var host = new URL(urlTemplate.replace('{domain}', 'example.com')).hostname;
                return 'https://t1.gstatic.com/faviconV2?client=SOCIAL&type=FAVICON&fallback_opts=TYPE,SIZE,URL&url=http://' + encodeURIComponent(host) + '&size=16';
            } catch (e) { return ''; }
        }

        function registrarIcon(r) {
            if (browserDnt) return fallbackIcon;
            var src = registrarFavicon(r.url_template);
            if (!src) return fallbackIcon;
            return '<img src="' + src + '" width="16" height="16" alt="" class="me-2" style="vertical-align:text-bottom" onerror="this.style.display=\'none\'">';
        }

        function buildRegisterButtons(domain) {
            if (!REGISTRARS.length) return '';
            var encodedDomain = encodeURIComponent(domain);

            if (REGISTRARS.length === 1) {
                var r = REGISTRARS[0];
                var url = r.url_template.replace('{domain}', encodedDomain);
                var target = r.open_in_new_tab ? ' target="_blank" rel="noopener noreferrer"' : '';
                return '<a href="' + url + '"' + target + ' class="btn btn-success btn-sm">' + registrarIcon(r) + 'Register at ' + esc(r.name) + '</a>';
            }

            // Multiple registrars — dropdown
            var html = '<div class="btn-group">';
            var first = REGISTRARS[0];
            var firstUrl = first.url_template.replace('{domain}', encodedDomain);
            var firstTarget = first.open_in_new_tab ? ' target="_blank" rel="noopener noreferrer"' : '';
            html += '<a href="' + firstUrl + '"' + firstTarget + ' class="btn btn-success btn-sm"><i class="bi bi-cart-plus me-1" aria-hidden="true"></i>Register</a>';
            html += '<button type="button" class="btn btn-success btn-sm dropdown-toggle dropdown-toggle-split" data-bs-toggle="dropdown" aria-expanded="false" aria-label="Choose registrar"><span class="visually-hidden">Choose registrar</span></button>';
            html += '<ul class="dropdown-menu" role="menu">';
            REGISTRARS.forEach(function (r) {
                var url = r.url_template.replace('{domain}', encodedDomain);
                var target = r.open_in_new_tab ? ' target="_blank" rel="noopener noreferrer"' : '';
                html += '<li><a class="dropdown-item" href="' + url + '"' + target + ' role="menuitem">' + registrarIcon(r) + esc(r.name) + '</a></li>';
            });
            html += '</ul></div>';
            return html;
        }

        var formattedResult = '';
        var rawWhoisText = '';
        var lastLookupData = null;
        var lastCompareData = null;
        var isRawView = false;

        // HTML escape helper to prevent XSS
        function esc(str) {
            var div = document.createElement('div');
            div.appendChild(document.createTextNode(str));
            return div.innerHTML;
        }
        var currentDomain = '';

        // ── URL parameter UI controls ──
        var urlParams = new URLSearchParams(window.location.search);
        var paramHideSecScore = urlParams.has('hideSecScore');
        var paramHideSummary = urlParams.has('hideDomainSummary');
        var paramOnly = urlParams.has('Only') ? urlParams.get('Only').toLowerCase().split(',').map(function (s) { return s.trim(); }).filter(Boolean) : [];
        // Map friendly names to data-tab values
        var tabNameMap = { whois: 'whois', dns: 'dns', email: 'email', ssl: 'ssl', subdomains: 'subdomains', security: 'security' };
        var paramOnlyTabs = paramOnly.map(function (n) { return tabNameMap[n] || n; }).filter(function (t) { return !!tabNameMap[t] || Object.values(tabNameMap).indexOf(t) !== -1; });
        // ?Only implies hideSecScore and hideDomainSummary
        if (paramOnlyTabs.length > 0) {
            paramHideSecScore = true;
            paramHideSummary = true;
        }

        // ── DNS Propagation auto-refresh ──
        var dnsPropAutoRefresh = null; // interval ID
        var dnsPropInterval = parseInt(localStorage.getItem('dnsPropInterval') || '60', 10);
        var dnsPropEnabled = localStorage.getItem('dnsPropAutoRefresh') === 'true';

        function renderDnsPropagation(dp) {
            var dpHtml = '<div class="card mt-3" id="dnsPropCard"><div class="card-header d-flex align-items-center justify-content-between flex-wrap gap-2">' +
                '<div><strong><i class="bi bi-globe me-1"></i>DNS Propagation</strong>' +
                (dp.consistent ? ' <span class="badge bg-success">Consistent</span>' : ' <span class="badge bg-warning">Inconsistent</span>') +
                ' <small class="text-muted">(' + dp.resolvers.length + ' servers)</small></div>' +
                '<div class="d-flex align-items-center gap-2">' +
                '<small id="dnsPropLastRefresh" class="text-muted"></small>' +
                '<div class="form-check form-switch mb-0">' +
                '<input class="form-check-input" type="checkbox" id="dnsPropAutoToggle"' + (dnsPropEnabled ? ' checked' : '') + ' title="Auto-refresh DNS propagation">' +
                '<label class="form-check-label small" for="dnsPropAutoToggle">Auto <select id="dnsPropIntervalSelect" class="form-select form-select-sm d-inline-block" style="width:auto;padding:0 1.5rem 0 0.3rem;font-size:0.75rem;height:1.5rem;">' +
                '<option value="15"' + (dnsPropInterval === 15 ? ' selected' : '') + '>15s</option>' +
                '<option value="30"' + (dnsPropInterval === 30 ? ' selected' : '') + '>30s</option>' +
                '<option value="60"' + (dnsPropInterval === 60 ? ' selected' : '') + '>60s</option>' +
                '<option value="120"' + (dnsPropInterval === 120 ? ' selected' : '') + '>2m</option>' +
                '<option value="300"' + (dnsPropInterval === 300 ? ' selected' : '') + '>5m</option>' +
                '</select></label></div>' +
                '<button class="btn btn-sm btn-outline-secondary" id="dnsPropManualRefresh" title="Refresh now"><i class="bi bi-arrow-clockwise"></i></button>' +
                '</div></div>';
            dpHtml += '<div class="card-body"><div class="table-responsive"><table class="table table-sm mb-0"><thead><tr><th>Resolver</th><th>Type</th><th>IP</th><th>Answer</th></tr></thead><tbody>';
            dp.resolvers.forEach(function (r) {
                // Flag suffix
                var flag = '';
                if (r.country_code && r.country_code !== 'GLOBAL') {
                    var cc = r.country_code.toUpperCase();
                    flag = ' ' + String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
                } else if (r.country_code === 'GLOBAL') {
                    flag = ' \uD83C\uDF10';
                }
                // Type column
                var typeBadge = '';
                if (r.type === 'security') {
                    typeBadge = '<span class="badge bg-info"><i class="bi bi-shield-check me-1"></i>Security</span>';
                } else if (r.type === 'family') {
                    typeBadge = '<span class="badge bg-warning text-dark"><i class="bi bi-people-fill me-1"></i>Family</span>';
                }
                dpHtml += '<tr><td class="fw-bold text-nowrap">' + esc(r.resolver) + flag + '</td><td>' + typeBadge + '</td><td><code>' + esc(r.ip) + '</code></td><td>' + (r.answers.length ? r.answers.map(esc).join(', ') : '<span class="text-muted">No answer</span>') + '</td></tr>';
            });
            dpHtml += '</tbody></table></div></div></div>';
            return dpHtml;
        }

        function refreshDnsPropagation() {
            if (!currentDomain) return;
            var fd = new FormData();
            fd.append('domain', currentDomain);
            fd.append('csrf_token', CSRF);
            fd.append('dns_propagation_only', '1');
            var refreshBtn = document.getElementById('dnsPropManualRefresh');
            if (refreshBtn) refreshBtn.classList.add('disabled');
            fetch('lookup?nocache=' + Date.now(), { method: 'POST', body: fd })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    if (data.dns_propagation) {
                        var card = document.getElementById('dnsPropCard');
                        if (card) {
                            var parent = card.parentNode;
                            var tmp = document.createElement('div');
                            tmp.innerHTML = renderDnsPropagation(data.dns_propagation);
                            parent.replaceChild(tmp.firstChild, card);
                            bindDnsPropControls();
                        }
                        var ts = document.getElementById('dnsPropLastRefresh');
                        if (ts) ts.textContent = 'Updated ' + new Date().toLocaleTimeString();
                    }
                })
                .catch(function () {})
                .finally(function () {
                    var btn = document.getElementById('dnsPropManualRefresh');
                    if (btn) btn.classList.remove('disabled');
                });
        }

        function startDnsPropAutoRefresh() {
            stopDnsPropAutoRefresh();
            if (dnsPropEnabled && currentDomain) {
                dnsPropAutoRefresh = setInterval(refreshDnsPropagation, dnsPropInterval * 1000);
            }
        }

        function stopDnsPropAutoRefresh() {
            if (dnsPropAutoRefresh) {
                clearInterval(dnsPropAutoRefresh);
                dnsPropAutoRefresh = null;
            }
        }

        function bindDnsPropControls() {
            var toggle = document.getElementById('dnsPropAutoToggle');
            var select = document.getElementById('dnsPropIntervalSelect');
            var manualBtn = document.getElementById('dnsPropManualRefresh');
            if (toggle) {
                toggle.onchange = function () {
                    dnsPropEnabled = this.checked;
                    localStorage.setItem('dnsPropAutoRefresh', dnsPropEnabled);
                    if (dnsPropEnabled) {
                        startDnsPropAutoRefresh();
                    } else {
                        stopDnsPropAutoRefresh();
                    }
                };
            }
            if (select) {
                select.onchange = function () {
                    dnsPropInterval = parseInt(this.value, 10);
                    localStorage.setItem('dnsPropInterval', dnsPropInterval);
                    if (dnsPropEnabled) startDnsPropAutoRefresh();
                };
            }
            if (manualBtn) {
                manualBtn.onclick = function () { refreshDnsPropagation(); };
            }
        }

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

        // ── Settings & Theme (Issue #181) ──
        var themeIcon = document.getElementById('themeIcon');
        var theme = localStorage.getItem('theme') || 'auto';
        var systemDarkMQ = window.matchMedia('(prefers-color-scheme: dark)');

        // Load saved settings as defaults (URL params override these)
        var savedSettings = JSON.parse(localStorage.getItem('appSettings') || '{}');
        if (!urlParams.has('hideSecScore') && savedSettings.hideSecScore) paramHideSecScore = true;
        if (!urlParams.has('hideDomainSummary') && savedSettings.hideSummary) paramHideSummary = true;
        if (paramOnlyTabs.length === 0 && savedSettings.defaultTabs && savedSettings.defaultTabs.length > 0 && savedSettings.defaultTabs.length < 6) {
            paramOnlyTabs = savedSettings.defaultTabs;
            if (savedSettings.defaultTabs.length > 0) {
                paramHideSecScore = true;
                paramHideSummary = true;
            }
        }

        applyTheme(theme);

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
            themeIcon.className = 'bi bi-gear-fill';
            document.querySelectorAll('[data-theme-value]').forEach(function (item) {
                item.classList.toggle('active', item.dataset.themeValue === t);
            });
        }

        // Settings modal controls
        function loadSettingsUI() {
            var s = JSON.parse(localStorage.getItem('appSettings') || '{}');
            document.getElementById('settingHideSecScore').checked = !!s.hideSecScore;
            document.getElementById('settingHideSummary').checked = !!s.hideSummary;
            var allTabs = ['whois', 'dns', 'email', 'ssl', 'subdomains', 'security'];
            var savedTabs = s.defaultTabs || allTabs;
            document.querySelectorAll('.setting-tab-check').forEach(function (cb) {
                cb.checked = savedTabs.indexOf(cb.value) !== -1;
            });
        }

        function saveSettings() {
            var checkedTabs = [];
            document.querySelectorAll('.setting-tab-check:checked').forEach(function (cb) {
                checkedTabs.push(cb.value);
            });
            var s = {
                hideSecScore: document.getElementById('settingHideSecScore').checked,
                hideSummary: document.getElementById('settingHideSummary').checked,
                defaultTabs: checkedTabs.length === 6 ? [] : checkedTabs, // empty = all tabs (full view)
            };
            localStorage.setItem('appSettings', JSON.stringify(s));
        }

        // Bind settings change events
        document.getElementById('settingHideSecScore').addEventListener('change', saveSettings);
        document.getElementById('settingHideSummary').addEventListener('change', saveSettings);
        document.querySelectorAll('.setting-tab-check').forEach(function (cb) {
            cb.addEventListener('change', saveSettings);
        });

        document.getElementById('settingsReset').addEventListener('click', function () {
            localStorage.removeItem('appSettings');
            localStorage.setItem('theme', 'auto');
            theme = 'auto';
            applyTheme('auto');
            loadSettingsUI();
        });

        // Load settings UI when modal opens
        document.getElementById('settingsModal').addEventListener('show.bs.modal', loadSettingsUI);

        // ── Lookup mode tabs (ARIA tab pattern with roving tabindex) ──
        var lookupTabs = Array.from(document.querySelectorAll('#lookupModeTabs .nav-link'));
        var panelMap = { single: 'singlePanel', bulk: 'bulkWhoisPanel', compare: 'comparePanel' };

        function activateLookupTab(tab) {
            lookupTabs.forEach(function (t) {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
                t.setAttribute('tabindex', '-1');
            });
            tab.classList.add('active');
            tab.setAttribute('aria-selected', 'true');
            tab.setAttribute('tabindex', '0');
            var mode = tab.dataset.mode;
            for (var m in panelMap) {
                var panel = document.getElementById(panelMap[m]);
                if (m === mode) { panel.removeAttribute('hidden'); panel.style.display = ''; }
                else { panel.setAttribute('hidden', ''); panel.style.display = 'none'; }
            }
        }

        lookupTabs.forEach(function (tab, idx) {
            // Set initial tabindex
            tab.setAttribute('tabindex', idx === 0 ? '0' : '-1');
            tab.addEventListener('click', function (e) { e.preventDefault(); activateLookupTab(this); this.focus(); });
            tab.addEventListener('keydown', function (e) {
                var idx = lookupTabs.indexOf(this);
                if (e.key === 'ArrowRight' || e.key === 'ArrowDown') { e.preventDefault(); var next = lookupTabs[(idx + 1) % lookupTabs.length]; activateLookupTab(next); next.focus(); }
                if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') { e.preventDefault(); var prev = lookupTabs[(idx - 1 + lookupTabs.length) % lookupTabs.length]; activateLookupTab(prev); prev.focus(); }
                if (e.key === 'Home') { e.preventDefault(); activateLookupTab(lookupTabs[0]); lookupTabs[0].focus(); }
                if (e.key === 'End') { e.preventDefault(); activateLookupTab(lookupTabs[lookupTabs.length - 1]); lookupTabs[lookupTabs.length - 1].focus(); }
            });
        });

        // Set initial hidden state on inactive panels
        document.getElementById('bulkWhoisPanel').setAttribute('hidden', '');
        document.getElementById('comparePanel').setAttribute('hidden', '');

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
        document.getElementById('clearHistory').addEventListener('click', function () {
            localStorage.removeItem('whoisHistory');
            renderHistory();
        });

        // Extract registrable domain from a hostname (mirrors PHP extractRegistrableDomain)
        var secondLevelTlds = ['co.uk','org.uk','me.uk','ac.uk','gov.uk','net.uk','sch.uk','com.au','net.au','org.au','edu.au','gov.au','co.nz','net.nz','org.nz','co.za','org.za','web.za','com.br','net.br','org.br','co.in','net.in','org.in','gen.in','firm.in','ind.in','co.jp','or.jp','ne.jp','ac.jp','go.jp','com.cn','net.cn','org.cn','com.tw','net.tw','org.tw','com.hk','org.hk','net.hk','edu.hk','gov.hk','co.kr','or.kr','ne.kr','com.sg','net.sg','org.sg','edu.sg','gov.sg','com.my','net.my','org.my','gov.my','edu.my','com.mx','net.mx','org.mx','gob.mx','com.ar','net.ar','org.ar','co.il','org.il','net.il','ac.il','gov.il','com.tr','net.tr','org.tr','gen.tr','co.id','or.id','go.id','web.id','com.ph','net.ph','org.ph','com.pk','net.pk','org.pk','gov.pk','edu.pk','com.ng','net.ng','org.ng','gov.ng','edu.ng','co.ke','or.ke','ne.ke','go.ke','ac.ke','com.eg','net.eg','org.eg','gov.eg','edu.eg','com.ua','net.ua','org.ua','gov.ua','edu.ua'];

        function extractDomain(host) {
            var parts = host.toLowerCase().replace(/^www\./, '').split('.');
            if (parts.length <= 2) {
                return parts.join('.');
            }
            // Check for known second-level TLDs (longest first)
            for (var len = Math.min(3, parts.length - 1); len >= 2; len--) {
                var candidate = parts.slice(-len).join('.');
                if (secondLevelTlds.indexOf(candidate) !== -1) {
                    return parts.slice(-(len + 1)).join('.');
                }
            }
            // Default: last two parts
            return parts.slice(-2).join('.');
        }

        // Clean stale history entries that contain full URLs or subdomains (Issue #177)
        (function cleanHistory() {
            var h = getHistory();
            var changed = false;
            h = h.map(function (entry) {
                var d = entry.domain;
                if (!d) {
                    return entry;
                }
                // Strip protocol and path to extract hostname
                var host = d;
                try {
                    if (d.indexOf('://') !== -1 || d.indexOf('/') !== -1) {
                        var url = d.indexOf('://') !== -1 ? d : 'http://' + d;
                        host = new URL(url).hostname;
                    }
                } catch (e) {}
                // Extract registrable domain (strip subdomains)
                var clean = extractDomain(host);
                if (clean !== d) {
                    entry.domain = clean;
                    changed = true;
                }
                return entry;
            });
            // Deduplicate after cleaning
            if (changed) {
                var seen = {};
                h = h.filter(function (entry) {
                    if (seen[entry.domain]) {
                        return false;
                    }
                    seen[entry.domain] = true;
                    return true;
                });
                localStorage.setItem('whoisHistory', JSON.stringify(h));
            }
        })();

        renderHistory();

        // ── Domain watch list (Issue #79) ──
        function getWatchList() { try { return JSON.parse(localStorage.getItem('whoisWatchList') || '[]'); } catch (e) { return []; } }
        function saveWatchList(list) { localStorage.setItem('whoisWatchList', JSON.stringify(list)); }

        function toggleWatch(domain, expiryDate) {
            var list = getWatchList();
            var idx = list.findIndex(function (w) { return w.domain === domain; });
            if (idx !== -1) {
                list.splice(idx, 1);
            } else {
                list.push({ domain: domain, expiry: expiryDate || null, added: Date.now() });
            }
            saveWatchList(list);
            updateWatchButtons();
        }

        function isWatched(domain) {
            return getWatchList().some(function (w) { return w.domain === domain; });
        }

        function updateWatchButtons() {
            document.querySelectorAll('.watchDomainBtn').forEach(function (btn) {
                var d = btn.dataset.domain;
                if (isWatched(d)) {
                    btn.innerHTML = '<i class="bi bi-eye-fill"></i>';
                    btn.classList.remove('btn-outline-secondary');
                    btn.classList.add('btn-info');
                    btn.setAttribute('aria-label', 'Unwatch domain');
                } else {
                    btn.innerHTML = '<i class="bi bi-eye"></i>';
                    btn.classList.remove('btn-info');
                    btn.classList.add('btn-outline-secondary');
                    btn.setAttribute('aria-label', 'Watch for expiry');
                }
            });
        }

        // Delegate watch button clicks
        document.addEventListener('click', function (e) {
            var btn = e.target.closest('.watchDomainBtn');
            if (!btn) return;
            var domain = btn.dataset.domain;
            var expiry = lastLookupData && lastLookupData.parsed ? lastLookupData.parsed['Expiry Date'] : null;
            toggleWatch(domain, expiry);
        });

        // Check watched domains on load for expiry warnings
        (function checkWatchedExpiry() {
            var list = getWatchList();
            var warnings = list.filter(function (w) {
                if (!w.expiry) return false;
                var exp = new Date(w.expiry);
                var diff = (exp - new Date()) / (1000 * 60 * 60 * 24);
                return diff > 0 && diff <= 30;
            });
            // Check for expired/dropped domains that may now be available (Issue #129)
            var expired = list.filter(function (w) {
                if (!w.expiry) return false;
                return new Date(w.expiry) < new Date();
            });
            if (expired.length > 0) {
                var expBanner = document.createElement('div');
                expBanner.className = 'alert alert-success alert-dismissible fade show m-2';
                expBanner.setAttribute('role', 'alert');
                expBanner.innerHTML = '<i class="bi bi-star-fill me-2"></i><strong>' + expired.length + ' watched domain(s) may have expired and could be available:</strong> ' +
                    expired.map(function (w) { return '<a href="?domain=' + encodeURIComponent(w.domain) + '">' + esc(w.domain) + '</a>'; }).join(', ') +
                    '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
                document.body.insertBefore(expBanner, document.body.firstChild);
            }
            if (warnings.length > 0) {
                var banner = document.createElement('div');
                banner.className = 'alert alert-warning alert-dismissible fade show m-2';
                banner.setAttribute('role', 'alert');
                banner.innerHTML = '<i class="bi bi-exclamation-triangle-fill me-2"></i><strong>' + warnings.length + ' watched domain(s) expiring within 30 days:</strong> ' +
                    warnings.map(function (w) { return '<a href="?domain=' + encodeURIComponent(w.domain) + '">' + esc(w.domain) + '</a>'; }).join(', ') +
                    ' <button class="btn btn-sm btn-outline-warning ms-2" id="exportIcsBtn"><i class="bi bi-calendar-event me-1"></i>Export to Calendar</button>' +
                    '<button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>';
                document.body.insertBefore(banner, document.body.firstChild);
                document.getElementById('exportIcsBtn').addEventListener('click', function () {
                    var ics = 'BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//mwWhoIs//EN\r\n';
                    warnings.forEach(function (w) {
                        var exp = new Date(w.expiry);
                        var dtStr = exp.toISOString().replace(/[-:]/g, '').split('.')[0] + 'Z';
                        ics += 'BEGIN:VEVENT\r\nDTSTART:' + dtStr + '\r\nDTEND:' + dtStr + '\r\nSUMMARY:Domain expiry: ' + w.domain + '\r\nDESCRIPTION:The domain ' + w.domain + ' expires on ' + exp.toLocaleDateString() + '\r\nEND:VEVENT\r\n';
                    });
                    ics += 'END:VCALENDAR';
                    var a = document.createElement('a');
                    a.href = URL.createObjectURL(new Blob([ics], { type: 'text/calendar' }));
                    a.download = 'domain-expiry.ics';
                    a.click();
                    URL.revokeObjectURL(a.href);
                });
            }
        })();

        // ── URL param auto-lookup ──
        var urlDomain = new URLSearchParams(window.location.search).get('domain');
        if (urlDomain) {
            document.getElementById('domain').value = urlDomain;
            triggerLookup(urlDomain);
        }

        // ── Client-side domain validation (Issue #78) ──
        var domainInput = document.getElementById('domain');
        var domainFeedback = document.getElementById('domainFeedback');
        var lookupBtn = document.getElementById('lookupBtn');
        var domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
        var ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
        var validationTimer = null;

        function validateDomainInput(val) {
            if (!val) {
                setValidation('', false);
                return;
            }
            // Strip protocol/www for validation
            val = val.replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').trim();
            if (domainRegex.test(val) || ipRegex.test(val)) {
                setValidation('', true);
            } else if (val.indexOf(' ') !== -1) {
                setValidation('Domain names cannot contain spaces', false);
            } else if (val.indexOf('.') === -1) {
                setValidation('Enter a full domain (e.g., example.com)', false);
            } else if (/[;|`$(){}\\<>'"!#]/.test(val)) {
                setValidation('Domain contains invalid characters', false);
            } else {
                setValidation('Invalid domain format', false);
            }
        }

        function setValidation(msg, valid) {
            if (!msg) {
                domainInput.classList.remove('is-invalid', 'is-valid');
                domainFeedback.textContent = '';
                lookupBtn.disabled = false;
            } else if (valid) {
                domainInput.classList.remove('is-invalid');
                domainInput.classList.add('is-valid');
                domainFeedback.textContent = '';
                lookupBtn.disabled = false;
            } else {
                domainInput.classList.remove('is-valid');
                domainInput.classList.add('is-invalid');
                domainFeedback.textContent = msg;
                lookupBtn.disabled = true;
            }
        }

        domainInput.addEventListener('input', function () {
            clearTimeout(validationTimer);
            var val = this.value.trim();
            validationTimer = setTimeout(function () {
                validateDomainInput(val);
            }, 300);
        });

        // Clear validation on focus
        domainInput.addEventListener('focus', function () {
            if (!this.value.trim()) {
                setValidation('', false);
            }
        });

        // ── Single form submit ──
        document.getElementById('whoisForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var d = document.getElementById('domain').value.trim();
            if (d) {
                setValidation('', false);
                triggerLookup(d);
            }
        });

        // ── Bulk form submit ──
        document.getElementById('bulkWhoisForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var text = document.getElementById('bulkDomains').value.trim();
            if (!text) return;
            var domains = text.split(/[\n,]+/)
                .map(function (d) {
                    return d.trim();
                })
                .filter(Boolean);
            var BULK_MAX = 50;
            if (domains.length > BULK_MAX) {
                showError('Maximum ' + BULK_MAX + ' domains per bulk lookup. You entered ' + domains.length + '.');
                return;
            }
            if (domains.length) {
                triggerBulkLookup(domains);
            }
        });

        // ── Bulk file import (Issue #117) ──
        document.getElementById('bulkFileInput').addEventListener('change', function () {
            var file = this.files[0];
            if (!file) return;
            var reader = new FileReader();
            reader.onload = function (e) {
                document.getElementById('bulkDomains').value = e.target.result;
            };
            reader.readAsText(file);
            this.value = ''; // Reset so same file can be re-imported
        });

        // ── Compare form submit (Issue #48) ──
        document.getElementById('compareForm').addEventListener('submit', function (e) {
            e.preventDefault();
            var d1 = document.getElementById('compareDomain1').value.trim();
            var d2 = document.getElementById('compareDomain2').value.trim();
            if (d1 && d2) {
                triggerCompare(d1, d2);
            }
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

                fetch('lookup?nocache=' + Date.now(), { method: 'POST', body: fd })
                    .then(function (r) {
                        return r.json();
                    })
                    .then(function (data) {
                        results[domain] = data;
                    })
                    .catch(function () {
                        results[domain] = { error: 'Lookup failed' };
                    })
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
            if (data1.parsed) {
                for (var k in data1.parsed) {
                    parsedKeys[k] = true;
                }
            }
            if (data2.parsed) {
                for (var k in data2.parsed) {
                    parsedKeys[k] = true;
                }
            }

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
            html += '<div class="mt-2 d-flex gap-2"><button class="btn btn-outline-secondary btn-sm" id="exportCompareJsonBtn"><i class="bi bi-filetype-json" aria-hidden="true"></i> Export JSON</button>' +
                '<button class="btn btn-outline-secondary btn-sm" id="exportCompareCsvBtn"><i class="bi bi-filetype-csv" aria-hidden="true"></i> Export CSV</button></div>';
            cr.innerHTML = html;
            cr.style.display = '';

            // Store for export
            lastCompareData = { domain1: d1, domain2: d2, data1: data1, data2: data2 };

            document.getElementById('exportCompareJsonBtn').addEventListener('click', function () {
                var exp = { compare_date: new Date().toISOString(), domains: [
                    { domain: d1, availability: data1.availability, parsed: data1.parsed, dns: data1.dns, ssl: data1.ssl },
                    { domain: d2, availability: data2.availability, parsed: data2.parsed, dns: data2.dns, ssl: data2.ssl }
                ]};
                var a = document.createElement('a');
                a.href = URL.createObjectURL(new Blob([JSON.stringify(exp, null, 2)], { type: 'application/json' }));
                a.download = d1 + '-vs-' + d2 + '.json';
                a.click();
                URL.revokeObjectURL(a.href);
            });

            document.getElementById('exportCompareCsvBtn').addEventListener('click', function () {
                var allKeys = {};
                if (data1.parsed) {
                    for (var k in data1.parsed) {
                        allKeys[k] = true;
                    }
                }
                if (data2.parsed) {
                    for (var k in data2.parsed) {
                        allKeys[k] = true;
                    }
                }
                var csv = 'Field,"' + d1 + '","' + d2 + '"\n';
                csv += '"Availability","' + (data1.availability || '') + '","' + (data2.availability || '') + '"\n';
                for (var key in allKeys) {
                    var v1 = data1.parsed && data1.parsed[key] ? (Array.isArray(data1.parsed[key]) ? data1.parsed[key].join('; ') : data1.parsed[key]) : '';
                    var v2 = data2.parsed && data2.parsed[key] ? (Array.isArray(data2.parsed[key]) ? data2.parsed[key].join('; ') : data2.parsed[key]) : '';
                    csv += '"' + key + '","' + v1 + '","' + v2 + '"\n';
                }
                var a = document.createElement('a');
                a.href = URL.createObjectURL(new Blob([csv], { type: 'text/csv' }));
                a.download = d1 + '-vs-' + d2 + '.csv';
                a.click();
                URL.revokeObjectURL(a.href);
            });
        }

        // ── Main lookup ──
        function triggerLookup(domain) {
            currentDomain = domain;
            showLoading(true);
            hideResults();

            var fd = new FormData();
            fd.append('domain', domain);
            fd.append('csrf_token', CSRF);

            fetch('lookup?nocache=' + Date.now(), { method: 'POST', body: fd })
                .then(function (r) {
                    if (!r.ok) {
                        throw new Error('Server error: ' + r.status);
                    }
                    return r.json();
                })
                .then(function (data) {
                    showLoading(false);
                    if (data.error) {
                        showError(data.error);
                        return;
                    }
                    // Use the cleaned domain from the backend (Issue #177)
                    if (data.domain) {
                        currentDomain = data.domain;
                        domainInput.value = data.domain;
                        updateURL(data.domain);
                    }
                    rawWhoisText = data.whois || '';
                    lastLookupData = data;
                    displayResults(data);
                    saveToHistory(currentDomain, data);
                })
                .catch(function (err) {
                    showLoading(false);
                    showError('Lookup failed: ' + err.message);
                });
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

                    fetch('lookup?nocache=' + Date.now(), { method: 'POST', body: fd })
                        .then(function (r) { return r.json(); })
                        .then(function (data) {
                            // Store for export (Issue #49)
                            bulkResultsData.push({ domain: domain, data: data });

                            var badgeClass = data.availability === 'available' ? 'bg-success' : 'bg-info';
                            var badgeText = data.availability === 'available' ? 'Available' : 'Registered';
                            var regBtn = data.availability === 'available' ? ' ' + buildRegisterButtons(domain) : '';
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
                var regButtons = buildRegisterButtons(currentDomain);
                avBadge.innerHTML = '<div class="alert alert-success d-flex align-items-center justify-content-between flex-wrap gap-2">' +
                    '<div><i class="bi bi-check-circle-fill me-2"></i><strong>' + esc(currentDomain) + '</strong> appears to be available!</div>' +
                    '<div class="d-flex gap-1 flex-wrap">' + regButtons + '</div></div>';
                avBadge.style.display = '';
                // Hide all result sections for available/unregistered domains (Issue #174)
                document.getElementById('dataSourceBadge').style.display = 'none';
                document.getElementById('parsedFields').style.display = 'none';
                document.getElementById('resultTabs').style.display = 'none';
                document.getElementById('whoisResultPane').style.display = 'none';
                document.getElementById('dnsResultPane').style.display = 'none';
                document.getElementById('emailSecurityPane').style.display = 'none';
                document.getElementById('sslPane').style.display = 'none';
                document.getElementById('subdomainsPane').style.display = 'none';
                document.getElementById('securityPane').style.display = 'none';
                document.getElementById('actionButtons').style.cssText = 'display:none !important';
                return;
            } else {
                var watchBtn = ' <button class="btn btn-outline-secondary btn-sm ms-auto watchDomainBtn" data-domain="' + esc(currentDomain) + '" aria-label="Watch for expiry"><i class="bi bi-eye"></i></button>';
                avBadge.innerHTML = '<div class="alert alert-info d-flex align-items-center">' +
                    '<div><i class="bi bi-info-circle-fill me-2"></i><strong>' + esc(currentDomain) + '</strong>&nbsp;is registered.</div>' + watchBtn + '</div>';
            }
            avBadge.style.display = '';

            // Screenshot preview (Issue #55)
            if (data.screenshot_url && data.availability === 'registered') {
                avBadge.innerHTML += '<div class="card mt-2"><div class="card-body p-2 text-center"><img src="' + data.screenshot_url + '" alt="Website preview of ' + esc(currentDomain) + '" class="img-fluid rounded" style="max-height:300px;" loading="lazy" onerror="this.parentElement.parentElement.style.display=\'none\'"></div></div>';
            }

            // Reset tab pane visibility — only WHOIS shown by default (Issue #178)
            document.getElementById('whoisResultPane').style.display = '';
            document.getElementById('dnsResultPane').style.display = 'none';
            document.getElementById('emailSecurityPane').style.display = 'none';
            document.getElementById('sslPane').style.display = 'none';
            document.getElementById('subdomainsPane').style.display = 'none';
            document.getElementById('securityPane').style.display = 'none';

            // Source badge
            var dsBadge = document.getElementById('dataSourceBadge');
            dsBadge.innerHTML = '<span class="badge bg-secondary">Source: ' + (data.data_source || 'whois').toUpperCase() + (data.cached ? ' (cached)' : '') + '</span>';
            if (data.rate_limit) {
                var rlClass = data.rate_limit.remaining <= 5 ? 'bg-danger' : (data.rate_limit.remaining <= 10 ? 'bg-warning' : 'bg-secondary');
                dsBadge.innerHTML += ' <span class="badge ' + rlClass + '" title="Rate limit">' + data.rate_limit.remaining + '/' + data.rate_limit.limit + ' remaining</span>';
            }
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
                        if (days <= 30) {
                            cls = ' class="table-danger"';
                        } else if (days <= 90) {
                            cls = ' class="table-warning"';
                        }
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

                // Domain age risk (Issue #95)
                if (data.domain_age_risk) {
                    var dar = data.domain_age_risk;
                    var darClass = dar.risk === 'high' ? 'alert-danger' : (dar.risk === 'medium' ? 'alert-warning' : 'alert-info');
                    var darIcon = dar.risk === 'high' ? 'bi-exclamation-triangle-fill' : (dar.risk === 'medium' ? 'bi-exclamation-circle' : 'bi-info-circle');
                    if (dar.risk !== 'low') {
                        html += '<div class="alert ' + darClass + ' mt-2 mb-0 small"><i class="bi ' + darIcon + ' me-1" aria-hidden="true"></i><strong>Domain Age:</strong> ' + esc(dar.reason) + ' (' + dar.days_old + ' days)</div>';
                    }
                }

                // WHOIS privacy (Issue #104)
                if (data.whois_privacy && data.whois_privacy.privacy_enabled) {
                    html += '<div class="alert alert-info mt-2 mb-0 small"><i class="bi bi-shield-lock me-1" aria-hidden="true"></i><strong>WHOIS Privacy:</strong> Registrant data is protected (' + esc(data.whois_privacy.indicators.slice(0, 3).join(', ')) + ')</div>';
                }

                // Hosting risk (Issue #105)
                if (data.hosting_risk && data.hosting_risk.risk !== 'low') {
                    var hrClass = data.hosting_risk.risk === 'high' ? 'alert-danger' : 'alert-warning';
                    html += '<div class="alert ' + hrClass + ' mt-2 mb-0 small"><i class="bi bi-geo-alt me-1" aria-hidden="true"></i><strong>Hosting:</strong> ' + esc(data.hosting_risk.reason) + ' (' + esc(data.hosting_risk.country) + ')</div>';
                }

                // PhishTank (Issue #98)
                if (data.phishtank && data.phishtank.is_phish) {
                    html += '<div class="alert alert-danger mt-2 mb-0 small"><i class="bi bi-bug me-1" aria-hidden="true"></i><strong>PhishTank:</strong> This domain is flagged as a known phishing site</div>';
                }

                // URLhaus (Issue #99)
                if (data.urlhaus && data.urlhaus.urls_total > 0) {
                    html += '<div class="alert alert-danger mt-2 mb-0 small"><i class="bi bi-radioactive me-1" aria-hidden="true"></i><strong>URLhaus:</strong> ' + data.urlhaus.urls_total + ' malware URL(s) associated with this domain</div>';
                }

                // Spamhaus (Issue #100)
                if (data.spamhaus && data.spamhaus.listed) {
                    html += '<div class="alert alert-danger mt-2 mb-0 small"><i class="bi bi-envelope-x me-1" aria-hidden="true"></i><strong>Spamhaus:</strong> IP is listed on ' + data.spamhaus.lists.length + ' blocklist(s): ' + esc(data.spamhaus.lists.map(function(l){ return l.label; }).join(', ')) + '</div>';
                }

                // AbuseIPDB (Issue #96)
                if (data.abuseipdb && data.abuseipdb.abuse_score > 0) {
                    var abuseClass = data.abuseipdb.abuse_score > 50 ? 'alert-danger' : 'alert-warning';
                    html += '<div class="alert ' + abuseClass + ' mt-2 mb-0 small"><i class="bi bi-flag me-1" aria-hidden="true"></i><strong>AbuseIPDB:</strong> Abuse confidence ' + data.abuseipdb.abuse_score + '%, ' + data.abuseipdb.total_reports + ' report(s)' + (data.abuseipdb.is_tor ? ' — Tor exit node' : '') + '</div>';
                }

                html += '</div></div>';
                pf.innerHTML = html;
                pf.style.display = '';
            }

            // IP geolocation (Issue #18)
            if (data.geolocation) {
                var geo = data.geolocation;
                var geoHtml = '<div class="card mt-3"><div class="card-header"><strong>Server Location</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                if (geo.city) {
                    geoHtml += '<tr><td class="fw-bold">City</td><td>' + esc(geo.city) + '</td></tr>';
                }
                if (geo.country) {
                    geoHtml += '<tr><td class="fw-bold">Country</td><td>' + esc(geo.country) + ' (' + esc(geo.country_code) + ')</td></tr>';
                }
                if (geo.isp) {
                    geoHtml += '<tr><td class="fw-bold">ISP</td><td>' + esc(geo.isp) + '</td></tr>';
                }
                if (geo.org) {
                    geoHtml += '<tr><td class="fw-bold">Organization</td><td>' + esc(geo.org) + '</td></tr>';
                }
                if (geo.as) {
                    geoHtml += '<tr><td class="fw-bold">AS</td><td>' + esc(geo.as) + '</td></tr>';
                }
                geoHtml += '</table></div></div>';
                document.getElementById('parsedFields').innerHTML += geoHtml;
                if (!paramHideSummary) document.getElementById('parsedFields').style.display = '';
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

                // MTA-STS (Issue #101)
                if (data.mta_sts) {
                    var stsIcon = data.mta_sts.found ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
                    esHtml += '<tr><td class="fw-bold">' + stsIcon + ' MTA-STS</td><td>' + (data.mta_sts.found ? 'configured' + (data.mta_sts.mode ? ' (' + esc(data.mta_sts.mode) + ')' : '') : 'not configured') + '</td></tr>';
                }

                // BIMI (Issue #102)
                if (data.bimi) {
                    var bimiIcon = data.bimi.found ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
                    esHtml += '<tr><td class="fw-bold">' + bimiIcon + ' BIMI</td><td>' + (data.bimi.found ? 'configured' + (data.bimi.logo_url ? ' — <a href="' + esc(data.bimi.logo_url) + '" target="_blank" rel="noopener">view logo</a>' : '') : 'not configured') + '</td></tr>';
                }

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

            // DNSSEC (Issue #93) — show in DNS results area
            if (data.dnssec) {
                var dsIcon = data.dnssec.signed ? '<i class="bi bi-shield-check text-success me-1"></i>' : '<i class="bi bi-shield-x text-warning me-1"></i>';
                var dsText = data.dnssec.signed ? 'DNSSEC is enabled' + (data.dnssec.ds_records ? ' (' + data.dnssec.ds_records + ' DS record(s))' : '') : 'DNSSEC is not enabled';
                var dnsPane = document.getElementById('dnsResultPane');
                dnsPane.innerHTML += '<div class="alert ' + (data.dnssec.signed ? 'alert-success' : 'alert-warning') + ' mt-2 small">' + dsIcon + '<strong>DNSSEC:</strong> ' + dsText + '</div>';
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

                // DANE/TLSA (Issue #103)
                if (data.dane_tlsa && data.dane_tlsa.found) {
                    sslHtml += '<div class="card mt-3"><div class="card-header"><strong>DANE/TLSA Records</strong></div><div class="card-body"><table class="table table-sm mb-0"><thead><tr><th>Usage</th><th>Selector</th><th>Matching</th><th>Data</th></tr></thead><tbody>';
                    data.dane_tlsa.records.forEach(function (r) {
                        sslHtml += '<tr><td>' + r.usage + '</td><td>' + r.selector + '</td><td>' + r.matching + '</td><td><code class="small">' + esc(r.data) + '</code></td></tr>';
                    });
                    sslHtml += '</tbody></table></div></div>';
                }

                // Certificate Transparency (Issue #94)
                if (data.cert_transparency) {
                    sslHtml += '<div class="card mt-3"><div class="card-header"><strong>Certificate Transparency</strong> <span class="badge bg-secondary">' + data.cert_transparency.total + ' certificates</span></div><div class="card-body"><table class="table table-sm mb-0"><thead><tr><th>Issuer</th><th>Common Name</th><th>Not Before</th><th>Not After</th></tr></thead><tbody>';
                    data.cert_transparency.recent.forEach(function (c) {
                        sslHtml += '<tr><td class="small">' + esc(c.issuer) + '</td><td>' + esc(c.common_name) + '</td><td>' + esc(c.not_before) + '</td><td>' + esc(c.not_after) + '</td></tr>';
                    });
                    sslHtml += '</tbody></table></div></div>';
                }

                document.getElementById('sslPane').innerHTML = sslHtml;
            }

            // Shodan (Issue #97) — show in subdomains/network area
            if (data.shodan) {
                var shHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-hdd-network me-1"></i>Exposed Services (Shodan)</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                shHtml += '<tr><td class="fw-bold">Open Ports</td><td>' + (data.shodan.ports.length ? data.shodan.ports.join(', ') : 'None detected') + '</td></tr>';
                if (data.shodan.os) {
                    shHtml += '<tr><td class="fw-bold">OS</td><td>' + esc(data.shodan.os) + '</td></tr>';
                }
                if (data.shodan.org) {
                    shHtml += '<tr><td class="fw-bold">Organization</td><td>' + esc(data.shodan.org) + '</td></tr>';
                }
                if (data.shodan.vulns && data.shodan.vulns.length) {
                    shHtml += '<tr class="table-danger"><td class="fw-bold">Known Vulnerabilities</td><td>' + data.shodan.vulns.map(esc).join(', ') + '</td></tr>';
                }
                shHtml += '</table></div></div>';
                document.getElementById('sslPane').innerHTML += shHtml;
            }

            // HTTP Security Headers (Issue #106)
            if (data.http_headers) {
                var hh = data.http_headers;
                var hhHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-shield-lock me-1"></i>HTTP Security Headers</strong> <span class="badge ' + (hh.grade <= 'B' ? 'bg-success' : (hh.grade <= 'D' ? 'bg-warning' : 'bg-danger')) + '">' + hh.grade + ' (' + hh.pass + '/' + hh.total + ')</span></div><div class="card-body"><table class="table table-sm mb-0">';
                hh.headers.forEach(function (h) {
                    var icon = h.present ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
                    hhHtml += '<tr><td class="fw-bold">' + icon + ' ' + esc(h.header) + '</td><td>' + (h.present ? '<code class="small">' + esc(h.value || '') + '</code>' : '<span class="text-muted">missing</span>') + '</td></tr>';
                });
                hhHtml += '</table></div></div>';
                document.getElementById('sslPane').innerHTML += hhHtml;
            }

            // TLS Audit (Issue #108)
            if (data.tls_audit) {
                var ta = data.tls_audit;
                var taHtml = '<div class="card mt-3"><div class="card-header"><strong>TLS Version Support</strong>' + (ta.insecure ? ' <span class="badge bg-danger">Insecure versions enabled</span>' : '') + '</div><div class="card-body"><table class="table table-sm mb-0">';
                if (ta.protocol) {
                    taHtml += '<tr><td class="fw-bold">Negotiated</td><td>' + esc(ta.protocol) + '</td></tr>';
                }
                if (ta.cipher) {
                    taHtml += '<tr><td class="fw-bold">Cipher</td><td><code>' + esc(ta.cipher) + '</code></td></tr>';
                }
                for (var ver in ta.versions) {
                    var cls = (ver === 'TLSv1.0' || ver === 'TLSv1.1') && ta.versions[ver] ? ' class="table-danger"' : '';
                    taHtml += '<tr' + cls + '><td class="fw-bold">' + esc(ver) + '</td><td>' + (ta.versions[ver] ? '<i class="bi bi-check-circle text-success"></i> Supported' : '<i class="bi bi-x-circle text-muted"></i> Not supported') + '</td></tr>';
                }
                taHtml += '</table></div></div>';
                document.getElementById('sslPane').innerHTML += taHtml;
            }

            // CAA Records (Issue #109)
            if (data.caa_records && data.caa_records.found) {
                var caaHtml = '<div class="card mt-3"><div class="card-header"><strong>CAA Records</strong></div><div class="card-body"><table class="table table-sm mb-0"><thead><tr><th>Tag</th><th>Value</th><th>Flag</th></tr></thead><tbody>';
                data.caa_records.records.forEach(function (r) {
                    caaHtml += '<tr><td>' + esc(r.tag) + '</td><td>' + esc(r.value) + '</td><td>' + r.flag + '</td></tr>';
                });
                caaHtml += '</tbody></table></div></div>';
                document.getElementById('sslPane').innerHTML += caaHtml;
            }

            // SMTP Security (Issue #110)
            if (data.smtp_security) {
                var sm = data.smtp_security;
                var smIcon = sm.starttls ? '<i class="bi bi-check-circle-fill text-success"></i>' : '<i class="bi bi-x-circle-fill text-danger"></i>';
                var esPane = document.getElementById('emailSecurityPane');
                esPane.innerHTML += '<div class="card mt-3"><div class="card-header"><strong>SMTP Security</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                esPane.innerHTML = esPane.innerHTML.slice(0, -1); // reopen
                var smHtml = '<div class="card mt-3"><div class="card-header"><strong>SMTP Security</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                smHtml += '<tr><td class="fw-bold">MX Server</td><td>' + esc(sm.mx_host) + '</td></tr>';
                if (sm.banner) {
                    smHtml += '<tr><td class="fw-bold">Banner</td><td><code class="small">' + esc(sm.banner) + '</code></td></tr>';
                }
                smHtml += '<tr><td class="fw-bold">' + smIcon + ' STARTTLS</td><td>' + (sm.starttls ? 'Supported' : 'Not supported') + '</td></tr>';
                smHtml += '</table></div></div>';
                document.getElementById('emailSecurityPane').innerHTML += smHtml;
            }

            // Redirect Chain (Issue #107)
            if (data.redirect_chain && data.redirect_chain.hops > 1) {
                var rc = data.redirect_chain;
                var rcHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-arrow-right-circle me-1"></i>Redirect Chain</strong>' + (rc.suspicious ? ' <span class="badge bg-warning">Excessive redirects</span>' : '') + (rc.http_to_https ? ' <span class="badge bg-info">HTTP→HTTPS</span>' : '') + '</div><div class="card-body"><ol class="mb-0 small">';
                rc.chain.forEach(function (hop) {
                    rcHtml += '<li><code>' + esc(hop.url) + '</code> <span class="badge bg-secondary">' + hop.status + '</span></li>';
                });
                rcHtml += '</ol></div></div>';
                document.getElementById('parsedFields').innerHTML += rcHtml;
                if (!paramHideSummary) document.getElementById('parsedFields').style.display = '';
            }

            // HTTP Versions (Issue #112)
            if (data.http_versions) {
                var hv = data.http_versions;
                var hvHtml = '<div class="card mt-3"><div class="card-header"><strong>Protocol Support</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                if (hv.protocol) {
                    hvHtml += '<tr><td class="fw-bold">Negotiated</td><td>' + esc(hv.protocol) + '</td></tr>';
                }
                hvHtml += '<tr><td class="fw-bold">HTTP/2</td><td>' + (hv.http2 ? '<i class="bi bi-check-circle text-success"></i> Yes' : '<i class="bi bi-x-circle text-muted"></i> No') + '</td></tr>';
                hvHtml += '<tr><td class="fw-bold">HTTP/3</td><td>' + (hv.http3 ? '<i class="bi bi-check-circle text-success"></i> Yes' : '<i class="bi bi-x-circle text-muted"></i> No') + '</td></tr>';
                hvHtml += '</table></div></div>';
                document.getElementById('sslPane').innerHTML += hvHtml;
            }

            // IPv6 (Issue #113)
            if (data.ipv6) {
                var v6Icon = data.ipv6.has_aaaa ? '<i class="bi bi-check-circle text-success me-1"></i>' : '<i class="bi bi-x-circle text-warning me-1"></i>';
                var v6Text = data.ipv6.has_aaaa ? 'IPv6 ready (' + data.ipv6.aaaa_records.map(esc).join(', ') + ')' : 'No AAAA records — IPv6 not configured';
                document.getElementById('dnsResultPane').innerHTML += '<div class="alert ' + (data.ipv6.has_aaaa ? 'alert-success' : 'alert-warning') + ' mt-2 small">' + v6Icon + '<strong>IPv6:</strong> ' + v6Text + '</div>';
            }

            // Response Times (Issue #114)
            if (data.response_times && data.response_times.dns_ms !== null) {
                var rt = data.response_times;
                var rtHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-speedometer2 me-1"></i>Response Times</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                rtHtml += '<tr><td class="fw-bold">DNS Resolution</td><td>' + rt.dns_ms + ' ms</td></tr>';
                rtHtml += '<tr><td class="fw-bold">Time to First Byte</td><td>' + rt.ttfb_ms + ' ms</td></tr>';
                rtHtml += '<tr><td class="fw-bold">Total</td><td>' + rt.total_ms + ' ms</td></tr>';
                rtHtml += '</table></div></div>';
                document.getElementById('parsedFields').innerHTML += rtHtml;
                if (!paramHideSummary) document.getElementById('parsedFields').style.display = '';
            }

            // NS Diversity (Issue #115)
            if (data.ns_diversity && !data.ns_diversity.diverse) {
                document.getElementById('dnsResultPane').innerHTML += '<div class="alert alert-warning mt-2 small"><i class="bi bi-exclamation-triangle me-1"></i><strong>NS Diversity:</strong> ' + esc(data.ns_diversity.warning) + '</div>';
            }

            // Reverse IP (Issue #111)
            if (data.reverse_ip && data.reverse_ip.count > 1) {
                var riHtml = '<div class="card mt-3"><div class="card-header"><strong>Shared Hosting</strong> <span class="badge bg-secondary">' + data.reverse_ip.count + ' domains on same IP</span></div><div class="card-body"><div class="small">' + data.reverse_ip.domains.slice(0, 15).map(esc).join(', ') + (data.reverse_ip.count > 15 ? '...' : '') + '</div></div></div>';
                document.getElementById('subdomainsPane').innerHTML += riHtml;
            }

            // Domain Suggestions — on-demand (Issue #164)
            if (data.availability === 'registered' || data.availability === 'unknown') {
                var sgBtnHtml = '<div class="mt-2" id="suggestContainer"><button class="btn btn-outline-primary btn-sm" id="suggestBtn"><i class="bi bi-lightbulb me-1"></i>Suggest Alternatives</button></div>';
                document.getElementById('availabilityBadge').innerHTML += sgBtnHtml;
                document.getElementById('suggestBtn').addEventListener('click', function () {
                    var btn = this;
                    btn.disabled = true;
                    btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Checking alternatives...';
                    var fd = new FormData();
                    fd.append('domain', currentDomain);
                    fetch('lookup?suggest=1', { method: 'POST', body: fd })
                        .then(function (r) { return r.json(); })
                        .then(function (result) {
                            var container = document.getElementById('suggestContainer');
                            if (result.suggestions && result.suggestions.length > 0) {
                                var html = '<div class="card mt-2"><div class="card-header"><strong><i class="bi bi-lightbulb me-1"></i>Available Alternatives</strong></div><div class="card-body"><div class="d-flex flex-wrap gap-2">';
                                result.suggestions.forEach(function (d) {
                                    html += '<a href="?domain=' + encodeURIComponent(d) + '" class="btn btn-outline-success btn-sm">' + esc(d) + '</a>';
                                });
                                html += '</div></div></div>';
                                container.innerHTML = html;
                            } else {
                                container.innerHTML = '<div class="alert alert-info mt-2 small"><i class="bi bi-info-circle me-1"></i>No available alternatives found for common TLDs.</div>';
                            }
                        })
                        .catch(function () {
                            btn.disabled = false;
                            btn.innerHTML = '<i class="bi bi-lightbulb me-1"></i>Suggest Alternatives';
                        });
                });
            }

            // Security Score (Issue #128, #175)
            if (data.security_score && !paramHideSecScore) {
                var ss = data.security_score;
                var ssColor = ss.grade <= 'B' ? 'success' : (ss.grade <= 'D' ? 'warning' : 'danger');

                // Store score history (Issue #138)
                var scoreHistory = {};
                try {
                    scoreHistory = JSON.parse(localStorage.getItem('securityScoreHistory') || '{}');
                } catch(e) {
                }
                if (!scoreHistory[currentDomain]) {
                    scoreHistory[currentDomain] = [];
                }
                scoreHistory[currentDomain].push({ ts: Date.now(), grade: ss.grade, score: ss.score });
                if (scoreHistory[currentDomain].length > 20) {
                    scoreHistory[currentDomain] = scoreHistory[currentDomain].slice(-20);
                }
                localStorage.setItem('securityScoreHistory', JSON.stringify(scoreHistory));

                // Build sparkline from history
                var history = scoreHistory[currentDomain] || [];
                var sparkline = '';
                if (history.length > 1) {
                    sparkline = '<div class="d-flex align-items-end gap-1 mt-1" style="height:20px;" title="Score history">';
                    history.forEach(function (h) {
                        var barH = Math.max(2, Math.round(h.score / 5));
                        var barC = h.score >= 75 ? '#198754' : (h.score >= 45 ? '#ffc107' : '#dc3545');
                        sparkline += '<div style="width:4px;height:' + barH + 'px;background:' + barC + ';border-radius:1px;"></div>';
                    });
                    sparkline += '</div>';
                }

                var ssHtml = '<div class="card mb-3"><div class="card-body d-flex align-items-center gap-3">' +
                    '<div class="text-center" style="min-width:60px"><span class="display-5 fw-bold text-' + ssColor + '">' + ss.grade + '</span><br><small class="text-muted">' + ss.score + '%</small></div>' +
                    '<div><strong>Security Score</strong><br><small class="text-muted">' + ss.passed + ' of ' + ss.total + ' checks passed</small>' +
                    '<div class="progress mt-1" style="height:6px;width:200px"><div class="progress-bar bg-' + ssColor + '" style="width:' + ss.score + '%"></div></div>' + sparkline + '</div></div></div>';
                document.getElementById('parsedFields').innerHTML = ssHtml + document.getElementById('parsedFields').innerHTML;
                if (!paramHideSummary) document.getElementById('parsedFields').style.display = '';

                // Security details tab (Issue #175)
                if (ss.details && ss.details.length) {
                    document.getElementById('resultTabs').style.display = '';
                    var secHtml = '<div class="card"><div class="card-header d-flex align-items-center justify-content-between">' +
                        '<strong><i class="bi bi-shield-check me-1"></i>Security Checks</strong>' +
                        '<span class="badge bg-' + ssColor + '">' + ss.grade + ' — ' + ss.score + '%</span></div>' +
                        '<div class="card-body"><div class="table-responsive"><table class="table table-sm mb-0">';
                    secHtml += '<thead><tr><th>Check</th><th>Status</th><th>Details</th><th class="text-nowrap">Guide</th></tr></thead><tbody>';
                    ss.details.forEach(function (d) {
                        var icon, badge;
                        if (d.status === 'pass') {
                            icon = '<i class="bi bi-check-circle-fill text-success"></i>';
                            badge = '<span class="badge bg-success">Pass</span>';
                        } else if (d.status === 'warn') {
                            icon = '<i class="bi bi-exclamation-triangle-fill text-warning"></i>';
                            badge = '<span class="badge bg-warning text-dark">Warning</span>';
                        } else {
                            icon = '<i class="bi bi-x-circle-fill text-danger"></i>';
                            badge = '<span class="badge bg-danger">Fail</span>';
                        }
                        secHtml += '<tr><td class="fw-bold">' + icon + ' ' + esc(d.name) + '</td><td>' + badge + '</td><td>' + esc(d.info);
                        if (d.recommendation) {
                            secHtml += '<br><small class="text-muted"><i class="bi bi-lightbulb me-1"></i>' + esc(d.recommendation) + '</small>';
                        }
                        secHtml += '</td><td>';
                        if (d.guide && d.status !== 'pass') {
                            secHtml += '<a href="' + esc(d.guide) + '" target="_blank" rel="noopener noreferrer" class="btn btn-sm btn-outline-primary"><i class="bi bi-box-arrow-up-right me-1"></i>Fix guide</a>';
                        }
                        secHtml += '</td></tr>';
                    });
                    secHtml += '</tbody></table></div></div></div>';
                    document.getElementById('securityPane').innerHTML = secHtml;
                }
            }

            // Tech Stack (Issue #124)
            if (data.tech_stack && data.tech_stack.length > 0) {
                var tsHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-stack me-1"></i>Technology Stack</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                data.tech_stack.forEach(function (t) {
                    tsHtml += '<tr><td class="fw-bold">' + esc(t.category) + '</td><td>' + esc(t.name) + '</td></tr>';
                });
                tsHtml += '</table></div></div>';
                document.getElementById('subdomainsPane').innerHTML += tsHtml;
            }

            // Robots.txt (Issue #125)
            if (data.robots_txt) {
                var rb = data.robots_txt;
                var rbHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-robot me-1"></i>Robots.txt & Sitemap</strong></div><div class="card-body"><table class="table table-sm mb-0">';
                rbHtml += '<tr><td class="fw-bold">robots.txt</td><td>' + (rb.robots_found ? '<i class="bi bi-check-circle text-success"></i> Found' : '<i class="bi bi-x-circle text-muted"></i> Not found') + '</td></tr>';
                rbHtml += '<tr><td class="fw-bold">sitemap.xml</td><td>' + (rb.sitemap_found ? '<i class="bi bi-check-circle text-success"></i> Found' : '<i class="bi bi-x-circle text-muted"></i> Not found') + '</td></tr>';
                if (rb.disallowed.length) {
                    rbHtml += '<tr><td class="fw-bold">Disallowed paths</td><td><code class="small">' + rb.disallowed.slice(0, 10).map(esc).join('</code>, <code class="small">') + '</code>' + (rb.disallowed.length > 10 ? ' ...' : '') + '</td></tr>';
                }
                if (rb.crawl_delay) {
                    rbHtml += '<tr><td class="fw-bold">Crawl delay</td><td>' + rb.crawl_delay + 's</td></tr>';
                }
                rbHtml += '</table></div></div>';
                document.getElementById('subdomainsPane').innerHTML += rbHtml;
            }

            // DNS Propagation (Issue #126)
            if (data.dns_propagation) {
                document.getElementById('dnsResultPane').innerHTML += renderDnsPropagation(data.dns_propagation);
                bindDnsPropControls();
                if (dnsPropEnabled) startDnsPropAutoRefresh();
            }

            // Multi-DNSBL (Issue #133)
            if (data.multi_dnsbl) {
                var db = data.multi_dnsbl;
                var dbHtml = '<div class="card mt-3"><div class="card-header"><strong><i class="bi bi-shield-exclamation me-1"></i>Blocklist Check</strong> <span class="badge ' + (db.listed ? 'bg-danger' : 'bg-success') + '">' + (db.listed ? db.lists.length + ' listed' : 'Clean') + '</span> <small class="text-muted">(' + db.total_checked + ' lists checked)</small></div>';
                if (db.listed) {
                    dbHtml += '<div class="card-body"><table class="table table-sm mb-0 table-danger">';
                    db.lists.forEach(function (l) {
                        dbHtml += '<tr><td>' + esc(l.label) + '</td><td><code class="small">' + esc(l.zone) + '</code></td></tr>';
                    });
                    dbHtml += '</table></div>';
                }
                dbHtml += '</div>';
                document.getElementById('emailSecurityPane').innerHTML += dbHtml;
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
                            if (sv !== pv) {
                                changes.push('<strong>' + k + ':</strong> ' + esc(pv || '(none)') + ' → ' + esc(sv));
                            }
                        }
                        if (changes.length) {
                            tlHtml += '<ul class="mb-0 small">';
                            changes.forEach(function (c) {
                                tlHtml += '<li>' + c + '</li>';
                            });
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

            // ── URL param: ?Only — filter visible tabs ──
            if (paramOnlyTabs.length > 0) {
                document.querySelectorAll('#resultTabs .nav-item').forEach(function (item) {
                    var link = item.querySelector('.nav-link');
                    if (link && paramOnlyTabs.indexOf(link.dataset.tab) === -1) {
                        item.style.display = 'none';
                    }
                });
                // Hide tab bar entirely if only one tab
                if (paramOnlyTabs.length === 1) {
                    document.getElementById('resultTabs').style.display = 'none';
                }
                // Focus the first allowed tab
                var firstTab = document.querySelector('#resultTabs .nav-link[data-tab="' + paramOnlyTabs[0] + '"]');
                if (firstTab) firstTab.click();
            }
        }

        // ── Result tabs ──
        document.querySelectorAll('#resultTabs .nav-link').forEach(function (tab) {
            tab.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelectorAll('#resultTabs .nav-link').forEach(function (t) {
                    t.classList.remove('active');
                    t.setAttribute('aria-selected', 'false');
                });
                this.classList.add('active');
                this.setAttribute('aria-selected', 'true');
                var t = this.dataset.tab;
                document.getElementById('whoisResultPane').style.display = t === 'whois' ? '' : 'none';
                document.getElementById('dnsResultPane').style.display = t === 'dns' ? '' : 'none';
                document.getElementById('emailSecurityPane').style.display = t === 'email' ? '' : 'none';
                document.getElementById('sslPane').style.display = t === 'ssl' ? '' : 'none';
                document.getElementById('subdomainsPane').style.display = t === 'subdomains' ? '' : 'none';
                document.getElementById('securityPane').style.display = t === 'security' ? '' : 'none';
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
        function updateToggleBtn() {
            document.getElementById('toggleViewBtn').textContent = isRawView ? 'Show Formatted Whois' : 'Show Raw Whois';
        }

        // ── Copy / Download ──
        document.getElementById('copyBtn').addEventListener('click', function () {
            navigator.clipboard.writeText(rawWhoisText.replace(/<[^>]*>/g, '')).then(function () {
                var b = document.getElementById('copyBtn');
                b.innerHTML = '<i class="bi bi-check"></i> Copied!';
                b.setAttribute('aria-label', 'Copied to clipboard');
                setTimeout(function () {
                    b.innerHTML = '<i class="bi bi-clipboard"></i> Copy';
                    b.setAttribute('aria-label', 'Copy WHOIS data to clipboard');
                }, 2000);
            });
        });
        document.getElementById('downloadBtn').addEventListener('click', function () {
            var a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([rawWhoisText.replace(/<[^>]*>/g, '')], { type: 'text/plain' }));
            a.download = currentDomain + '-whois.txt';
            a.click();
            URL.revokeObjectURL(a.href);
        });

        // ── Export single lookup as JSON (Issue #73) ──
        document.getElementById('exportJsonSingleBtn').addEventListener('click', function () {
            if (!lastLookupData) {
                return;
            }
            var exportData = {
                domain: currentDomain,
                lookup_date: new Date().toISOString(),
                availability: lastLookupData.availability,
                data_source: lastLookupData.data_source,
                parsed: lastLookupData.parsed,
                dns: lastLookupData.dns,
                ssl: lastLookupData.ssl,
                email_security: lastLookupData.email_security,
                geolocation: lastLookupData.geolocation,
                subdomains: lastLookupData.subdomains
            };
            var a = document.createElement('a');
            a.href = URL.createObjectURL(new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' }));
            a.download = currentDomain + '-whois.json';
            a.click();
            URL.revokeObjectURL(a.href);
        });

        // ── WHOIS diff: cached vs fresh (Issue #21) ──
        document.getElementById('diffBtn').addEventListener('click', function () {
            if (!currentDomain || !rawWhoisText) {
                return;
            }
            var cachedWhois = rawWhoisText.replace(/<[^>]*>/g, '');
            var btn = this;
            btn.disabled = true;
            btn.innerHTML = '<i class="bi bi-hourglass-split"></i> Fetching fresh...';

            var fd = new FormData();
            fd.append('domain', currentDomain);
            fd.append('csrf_token', CSRF);

            fetch('lookup?nocache=' + Date.now() + '&source=whois', { method: 'POST', body: fd })
                .then(function (r) {
                    return r.json();
                })
                .then(function (data) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Refresh &amp; Diff';
                    if (data.error) {
                        showError(data.error);
                        return;
                    }
                    var freshWhois = (data.whois || '').replace(/<[^>]*>/g, '');

                    // Build diff view
                    var cachedLines = cachedWhois.split('\n');
                    var freshLines = freshWhois.split('\n');
                    var diffHtml = '<div class="card"><div class="card-header"><strong><i class="bi bi-arrow-left-right me-2"></i>WHOIS Diff</strong> <small class="text-muted">(cached vs fresh)</small></div><div class="card-body">';

                    if (cachedWhois === freshWhois) {
                        diffHtml += '<div class="alert alert-success mb-0"><i class="bi bi-check-circle me-2"></i>No changes detected — cached and fresh results are identical.</div>';
                    } else {
                        diffHtml += '<pre class="mb-0" style="font-size:0.8rem; max-height:400px; overflow-y:auto;">';
                        var maxLen = Math.max(cachedLines.length, freshLines.length);
                        for (var i = 0; i < maxLen; i++) {
                            var cl = cachedLines[i] || '';
                            var fl = freshLines[i] || '';
                            if (cl === fl) {
                                diffHtml += ' ' + esc(fl) + '\n';
                            } else {
                                if (cl) {
                                    diffHtml += '<span style="background:#fdd;color:#900;">-' + esc(cl) + '</span>\n';
                                }
                                if (fl) {
                                    diffHtml += '<span style="background:#dfd;color:#060;">+' + esc(fl) + '</span>\n';
                                }
                            }
                        }
                        diffHtml += '</pre>';
                    }
                    diffHtml += '</div></div>';
                    document.getElementById('result').innerHTML = diffHtml;
                })
                .catch(function (err) {
                    btn.disabled = false;
                    btn.innerHTML = '<i class="bi bi-arrow-repeat"></i> Refresh &amp; Diff';
                    showError('Diff failed: ' + err.message);
                });
        });

        // ── QR code (Issue #50) ──
        document.getElementById('qrCodeBtn').addEventListener('click', function () {
            var shareUrl = window.location.origin + window.location.pathname + '?domain=' + encodeURIComponent(currentDomain);
            if (browserDnt) {
                // DNT: show URL only, skip external QR API
                document.getElementById('qrCodeImg').style.display = 'none';
                document.getElementById('qrCodeUrl').textContent = shareUrl;
            } else {
                var qrApiUrl = 'https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=' + encodeURIComponent(shareUrl);
                document.getElementById('qrCodeImg').style.display = '';
                document.getElementById('qrCodeImg').src = qrApiUrl;
                document.getElementById('qrCodeUrl').textContent = shareUrl;
            }
            var modal = new bootstrap.Modal(document.getElementById('qrCodeModal'));
            modal.show();
        });

        // ── PDF export (Issue #120) ──
        document.getElementById('printPdfBtn').addEventListener('click', function () {
            window.print();
        });

        // ── Share link (Issue #121) ──
        document.getElementById('shareBtn').addEventListener('click', function () {
            var shareUrl = window.location.origin + window.location.pathname + '?domain=' + encodeURIComponent(currentDomain);
            navigator.clipboard.writeText(shareUrl).then(function () {
                var b = document.getElementById('shareBtn');
                b.innerHTML = '<i class="bi bi-check"></i> Copied!';
                b.setAttribute('aria-label', 'Link copied');
                setTimeout(function () {
                    b.innerHTML = '<i class="bi bi-share"></i> Share';
                    b.setAttribute('aria-label', 'Copy share link');
                }, 2000);
            });
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
            ['availabilityBadge', 'dataSourceBadge', 'parsedFields', 'resultTabs', 'dnsResultPane', 'emailSecurityPane', 'sslPane', 'subdomainsPane', 'securityPane', 'bulkResults', 'bulkProgress', 'bulkExportButtons', 'compareResults'].forEach(function (id) {
                document.getElementById(id).style.display = 'none';
            });
            document.getElementById('whoisResultPane').style.display = '';
            document.getElementById('result').innerHTML = '';
            document.getElementById('dnsResultPane').innerHTML = '';
            stopDnsPropAutoRefresh();
            document.getElementById('emailSecurityPane').innerHTML = '';
            document.getElementById('sslPane').innerHTML = '';
            document.getElementById('subdomainsPane').innerHTML = '';
            document.getElementById('securityPane').innerHTML = '';
            document.getElementById('parsedFields').innerHTML = '';
            document.getElementById('actionButtons').style.cssText = 'display:none !important';
            document.getElementById('emptyState').style.display = 'none';
            // Reset active tab to WHOIS (Issue #178)
            document.querySelectorAll('#resultTabs .nav-link').forEach(function (t) {
                t.classList.remove('active');
                t.setAttribute('aria-selected', 'false');
            });
            var whoisTab = document.getElementById('rtab-whois');
            if (whoisTab) {
                whoisTab.classList.add('active');
                whoisTab.setAttribute('aria-selected', 'true');
            }
        }

        function showError(msg) {
            document.getElementById('result').innerHTML = '<div class="alert alert-danger fade-in" role="alert"><i class="bi bi-exclamation-triangle-fill me-2"></i>' + esc(msg) + '</div>';
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

        // ── Keyboard shortcuts (Issue #76) ──
        document.addEventListener('keydown', function (e) {
            var tag = (e.target.tagName || '').toLowerCase();
            var isInput = tag === 'input' || tag === 'textarea' || tag === 'select';

            // "/" or Ctrl+K — focus domain input
            if ((e.key === '/' || (e.ctrlKey && e.key === 'k')) && !isInput) {
                e.preventDefault();
                document.getElementById('domain').focus();
                return;
            }

            // Ctrl+Enter — submit current visible form
            if (e.ctrlKey && e.key === 'Enter') {
                var sp = document.getElementById('singlePanel');
                var bp = document.getElementById('bulkWhoisPanel');
                var cp = document.getElementById('comparePanel');
                if (sp.style.display !== 'none') {
                    document.getElementById('whoisForm').dispatchEvent(new Event('submit'));
                } else if (bp.style.display !== 'none') {
                    document.getElementById('bulkWhoisForm').dispatchEvent(new Event('submit'));
                } else if (cp.style.display !== 'none') {
                    document.getElementById('compareForm').dispatchEvent(new Event('submit'));
                }
                return;
            }

            // Ctrl+Shift+C — copy WHOIS result
            if (e.ctrlKey && e.shiftKey && e.key === 'C') {
                var copyBtn = document.getElementById('copyBtn');
                if (copyBtn && copyBtn.offsetParent !== null) {
                    copyBtn.click();
                    return;
                }
            }

            // Number keys 1-5 — switch result tabs (only when not in input)
            if (!isInput && !e.ctrlKey && !e.altKey && !e.metaKey) {
                var tabMap = { '1': 'whois', '2': 'dns', '3': 'email', '4': 'ssl', '5': 'subdomains' };
                if (tabMap[e.key] && document.getElementById('resultTabs').style.display !== 'none') {
                    var tabLink = document.querySelector('#resultTabs [data-tab="' + tabMap[e.key] + '"]');
                    if (tabLink) {
                        tabLink.click();
                        e.preventDefault();
                    }
                    return;
                }

                // "?" — show shortcuts help
                if (e.key === '?') {
                    e.preventDefault();
                    var helpHtml = '<div class="card"><div class="card-header"><strong>Keyboard Shortcuts</strong></div><div class="card-body"><table class="table table-sm mb-0">' +
                        '<tr><td><kbd>/</kbd> or <kbd>Ctrl+K</kbd></td><td>Focus search input</td></tr>' +
                        '<tr><td><kbd>Ctrl+Enter</kbd></td><td>Submit current form</td></tr>' +
                        '<tr><td><kbd>Ctrl+Shift+C</kbd></td><td>Copy WHOIS result</td></tr>' +
                        '<tr><td><kbd>1</kbd>-<kbd>5</kbd></td><td>Switch result tabs</td></tr>' +
                        '<tr><td><kbd>?</kbd></td><td>Show this help</td></tr>' +
                        '</table></div></div>';
                    var helpEl = document.getElementById('result');
                    if (helpEl.innerHTML.indexOf('Keyboard Shortcuts') === -1) {
                        helpEl.innerHTML = helpHtml;
                    }
                }
            }
        });
    });

    // ── PWA Service Worker registration — production only (Issue #25) ──
    <?php if (empty($app["Application"]["Version"]["Development"]["Status"])): ?>
    if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('sw.js').catch(function () {
        });
    }
    <?php endif; ?>

    // ── PWA install prompt — production only (Issue #170) ──
    <?php if (empty($app["Application"]["Version"]["Development"]["Status"])): ?>
    (function () {
        var deferredPrompt = null;
        var banner = document.getElementById('pwaInstallBanner');
        var installBtn = document.getElementById('pwaInstallBtn');
        var dismissBtn = document.getElementById('pwaInstallDismiss');

        if (window.matchMedia('(display-mode: standalone)').matches) {
            return;
        }

        var dismissed = localStorage.getItem('pwaInstallDismissed');
        if (dismissed && (Date.now() - parseInt(dismissed)) < 7 * 24 * 60 * 60 * 1000) {
            return;
        }

        window.addEventListener('beforeinstallprompt', function (e) {
            e.preventDefault();
            deferredPrompt = e;
            banner.style.display = 'flex';
        });

        installBtn.addEventListener('click', function () {
            if (!deferredPrompt) {
                return;
            }
            deferredPrompt.prompt();
            deferredPrompt.userChoice.then(function (result) {
                banner.style.display = 'none';
                deferredPrompt = null;
            });
        });

        dismissBtn.addEventListener('click', function () {
            banner.style.display = 'none';
            localStorage.setItem('pwaInstallDismissed', Date.now().toString());
            deferredPrompt = null;
        });

        window.addEventListener('appinstalled', function () {
            banner.style.display = 'none';
            deferredPrompt = null;
        });
    })();
    <?php endif; ?>
    </script>
</body>
</html>

