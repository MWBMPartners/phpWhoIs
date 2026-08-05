<?php
/**
 * mwWhoIs — TLD Reference
 * A searchable browser of every IANA-delegated top-level domain, grouped
 * by category. Data is sourced from the IANA root-zone list which is
 * refreshed daily by the lookup pipeline.
 */

require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'session_config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'asset_version.php';

// ─── Security headers ───
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net; img-src 'self' data:; connect-src 'self'");

// ─── Constants (must match lookup.php) ───
define('IANA_TLD_URL', 'https://data.iana.org/TLD/tlds-alpha-by-domain.txt');
define('IANA_TLD_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'tlds.txt');
define('PSL_ICANN_URL', 'https://publicsuffix.org/list/public_suffix_list.dat');
define('SL_SUFFIXES_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'second_level_suffixes.txt');
define('TLD_META_PATH', __DIR__ . DIRECTORY_SEPARATOR . 'tld_metadata.json');
define('CACHE_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'mwwhois_cache');
define('CACHE_TTL', 900);
define('RATE_LIMIT_MAX', 30);
define('RATE_LIMIT_WINDOW', 60);
define('MAX_DOMAIN_LENGTH', 253);
define('MAX_POST_SIZE', 1024);

$config = [];
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'config.php';
}
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'functions.php';

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}

$appName = isset($app["Application"]["Name"]) && $app["Application"]["Name"]
    ? $app["Application"]["Name"]
    : 'WHOIS Lookup';
$poweredBy = $appName;
if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]) {
    $poweredBy .= '/' . $app["Application"]["Version"]["Number"];
}
header('X-Powered-By: ' . $poweredBy);

// Ensure the IANA list is fresh (throttled to once per day inside the helper).
updateTldDataIfNeeded();

$tldGroups = getTldsByCategory();
$tldMeta = file_exists(TLD_META_PATH) ? json_decode(file_get_contents(TLD_META_PATH), true) : null;
$tldLastUpdated = (is_array($tldMeta) && isset($tldMeta['checked_at']))
    ? date('j M Y H:i \U\T\C', (int)$tldMeta['checked_at'])
    : null;

$totalTlds = array_sum(array_map('count', $tldGroups));

// JSON export for machine consumers: /tlds.php?format=json
if (isset($_GET['format']) && strtolower(trim($_GET['format'])) === 'json') {
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode([
        'total' => $totalTlds,
        'last_updated' => $tldLastUpdated,
        'source' => IANA_TLD_URL,
        'categories' => $tldGroups,
    ], JSON_PRETTY_PRINT);
    exit;
}

// ── Category display metadata ──
$categoryMeta = [
    'generic'        => ['label' => 'Generic (gTLD)',         'desc' => 'The original unrestricted generic TLDs.',                      'icon' => 'bi-globe'],
    'country'        => ['label' => 'Country-code (ccTLD)',   'desc' => 'Two-letter country and territory TLDs (plus IDN ccTLDs).',    'icon' => 'bi-flag'],
    'sponsored'      => ['label' => 'Sponsored',              'desc' => 'Restricted TLDs run by a sponsoring organisation (.edu, .gov, .museum, …).', 'icon' => 'bi-award'],
    'new_gtld'       => ['label' => 'New gTLD',               'desc' => 'TLDs delegated through the 2012+ ICANN new gTLD programme.',    'icon' => 'bi-stars'],
    'infrastructure' => ['label' => 'Infrastructure',         'desc' => 'TLDs reserved for internet infrastructure (e.g. .arpa).',       'icon' => 'bi-gear'],
];
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — TLD Reference</title>
    <meta name="description" content="Searchable reference of every IANA-delegated top-level domain, grouped by category and kept up to date daily from the IANA root zone.">
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo assetVersion(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
    <style>
        .tld-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 6px; }
        .tld-chip {
            display: inline-flex; align-items: center; justify-content: space-between;
            padding: 6px 10px; border: 1px solid var(--bs-border-color);
            border-radius: 6px; text-decoration: none; font-family: var(--bs-font-monospace);
            font-size: 0.9em; color: var(--bs-body-color); background: var(--bs-body-bg);
            transition: background 120ms, border-color 120ms;
        }
        .tld-chip:hover { background: var(--bs-tertiary-bg); border-color: var(--bs-primary); }
        .tld-chip .bi { opacity: 0.5; font-size: 0.85em; margin-left: 6px; }
        .tld-chip.hidden { display: none; }
        .tld-category.empty { display: none; }
        .tld-category-header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; }
        .tld-count-badge { font-variant-numeric: tabular-nums; }
        .tld-search-wrap { position: sticky; top: 0; z-index: 10; padding: 12px 0; background: var(--bs-body-bg); }
    </style>
</head>
<body>
    <header class="header-form" style="padding: 15px 20px;">
        <div class="d-flex align-items-center justify-content-between">
            <h1 class="mb-0" style="font-size: 1.2rem;">
                <a href="/"><img src="assets/images/logo-notext.svg" alt="" style="height: 32px; vertical-align: middle; margin-right: 8px;" aria-hidden="true"><?php echo htmlspecialchars($appName); ?></a>
                <small class="text-muted" style="font-weight: 400; font-size: 0.8em;">— TLD Reference</small>
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
    <div class="container py-4" style="max-width: 1100px; padding-bottom: 80px;">

        <p class="lead mb-2">Every TLD currently delegated in the DNS root zone — generic, country-code, sponsored, new gTLDs, and infrastructure.</p>
        <p class="text-muted small mb-4">
            <strong><?php echo number_format($totalTlds); ?></strong> TLDs total.
            Data from <a href="<?php echo htmlspecialchars(IANA_TLD_URL); ?>" target="_blank" rel="noopener noreferrer">IANA</a>,
            <?php if ($tldLastUpdated): ?>refreshed <time datetime="<?php echo date('c', (int)$tldMeta['checked_at']); ?>"><?php echo htmlspecialchars($tldLastUpdated); ?></time>.<?php else: ?>refreshed automatically once per day.<?php endif; ?>
            Click any TLD to view its entry in the IANA root-zone database.
            <a href="tlds.php?format=json" class="text-muted">JSON</a>.
        </p>

        <?php if ($totalTlds === 0): ?>
            <div class="alert alert-warning">
                The local TLD list hasn't been fetched yet. Run a lookup on the home page to populate it, or wait for the daily refresh.
            </div>
        <?php else: ?>

        <div class="tld-search-wrap">
            <div class="input-group input-group-lg">
                <span class="input-group-text bg-transparent" id="tldSearchLabel"><i class="bi bi-search" aria-hidden="true"></i></span>
                <input type="search" class="form-control" id="tldSearch" placeholder="Filter TLDs (e.g. io, uk, shop, xn--…)" autocomplete="off" spellcheck="false" aria-label="Filter TLDs" aria-describedby="tldSearchLabel">
                <button class="btn btn-outline-secondary" type="button" id="tldClear" aria-label="Clear filter"><i class="bi bi-x-lg" aria-hidden="true"></i></button>
            </div>
            <div class="mt-2 d-flex flex-wrap gap-2" role="group" aria-label="Filter by category">
                <button class="btn btn-sm btn-outline-primary active" data-category-filter="all" type="button">All</button>
                <?php foreach ($categoryMeta as $cat => $meta):
                    $count = count($tldGroups[$cat] ?? []);
                    if ($count === 0) continue; ?>
                    <button class="btn btn-sm btn-outline-secondary" data-category-filter="<?php echo htmlspecialchars($cat); ?>" type="button">
                        <i class="bi <?php echo htmlspecialchars($meta['icon']); ?> me-1" aria-hidden="true"></i><?php echo htmlspecialchars($meta['label']); ?>
                        <span class="badge bg-secondary ms-1 tld-count-badge"><?php echo number_format($count); ?></span>
                    </button>
                <?php endforeach; ?>
            </div>
            <div id="tldNoResults" class="alert alert-info mt-3" style="display:none;">
                <i class="bi bi-info-circle me-1" aria-hidden="true"></i>No TLDs match that filter.
            </div>
        </div>

        <?php foreach ($categoryMeta as $cat => $meta):
            $items = $tldGroups[$cat] ?? [];
            if (empty($items)) continue; ?>
            <section class="tld-category mb-4" data-category="<?php echo htmlspecialchars($cat); ?>">
                <div class="tld-category-header mb-2">
                    <h2 class="h5 mb-0">
                        <i class="bi <?php echo htmlspecialchars($meta['icon']); ?> me-1" aria-hidden="true"></i>
                        <?php echo htmlspecialchars($meta['label']); ?>
                        <span class="badge bg-secondary ms-1 tld-count-badge"><?php echo number_format(count($items)); ?></span>
                    </h2>
                    <small class="text-muted"><?php echo htmlspecialchars($meta['desc']); ?></small>
                </div>
                <div class="tld-grid">
                    <?php foreach ($items as $tld): ?>
                        <a class="tld-chip" href="https://www.iana.org/domains/root/db/<?php echo urlencode($tld); ?>.html" target="_blank" rel="noopener noreferrer" data-tld="<?php echo htmlspecialchars($tld); ?>" title="View .<?php echo htmlspecialchars($tld); ?> in the IANA root-zone database">
                            <span>.<?php echo htmlspecialchars($tld); ?></span>
                            <i class="bi bi-box-arrow-up-right" aria-hidden="true"></i>
                        </a>
                    <?php endforeach; ?>
                </div>
            </section>
        <?php endforeach; ?>

        <?php endif; ?>
    </div>
    </div>

    <?php require __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'footer.php'; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    (function () {
        var search = document.getElementById('tldSearch');
        var clearBtn = document.getElementById('tldClear');
        var catButtons = document.querySelectorAll('[data-category-filter]');
        var categories = document.querySelectorAll('.tld-category');
        var chips = document.querySelectorAll('.tld-chip');
        var noResults = document.getElementById('tldNoResults');
        var activeCategory = 'all';

        function applyFilter() {
            var q = (search.value || '').trim().toLowerCase();
            var total = 0;

            categories.forEach(function (section) {
                var cat = section.getAttribute('data-category');
                var matchesCategory = (activeCategory === 'all' || activeCategory === cat);
                var visible = 0;
                section.querySelectorAll('.tld-chip').forEach(function (chip) {
                    var tld = chip.getAttribute('data-tld');
                    var matchesText = (q === '' || tld.indexOf(q) !== -1);
                    var show = matchesCategory && matchesText;
                    chip.classList.toggle('hidden', !show);
                    if (show) visible++;
                });
                section.classList.toggle('empty', visible === 0);
                total += visible;
            });

            noResults.style.display = (total === 0) ? '' : 'none';
        }

        if (search) {
            search.addEventListener('input', applyFilter);
            // Support /tlds.php?q=xxx as a deep-link filter
            var params = new URLSearchParams(window.location.search);
            var preset = params.get('q');
            if (preset) { search.value = preset; applyFilter(); }
        }
        if (clearBtn) {
            clearBtn.addEventListener('click', function () {
                search.value = '';
                search.focus();
                applyFilter();
            });
        }
        catButtons.forEach(function (btn) {
            btn.addEventListener('click', function () {
                activeCategory = btn.getAttribute('data-category-filter');
                catButtons.forEach(function (b) {
                    var isActive = (b === btn);
                    b.classList.toggle('active', isActive);
                    b.classList.toggle('btn-outline-primary', isActive);
                    b.classList.toggle('btn-outline-secondary', !isActive);
                });
                applyFilter();
            });
        });

        // ── Theme toggle (matches other pages) ──
        var themeIcon = document.getElementById('themeIcon');
        var theme = localStorage.getItem('theme') || 'auto';
        var systemDarkMQ = window.matchMedia('(prefers-color-scheme: dark)');
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
            if (t === 'auto') resolved = systemDarkMQ.matches ? 'dark' : 'light';
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
            if (themeIcon) themeIcon.className = icons[t] || 'bi bi-circle-half';
            document.querySelectorAll('[data-theme-value]').forEach(function (item) {
                item.classList.toggle('active', item.dataset.themeValue === t);
            });
        }
    })();
    </script>
</body>
</html>
