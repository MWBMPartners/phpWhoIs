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

// ─── Debug mode ───
$modeDev = false;
$modeDebug = false;

if (isset($_GET['dev'])) {
    $modeDev = true;

    if (isset($_GET['debug'])) {
        $modeDebug = true;
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
    <title>Whois Lookup</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.3/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Header -->
    <div class="header-form">
        <div class="d-flex justify-content-between align-items-center mb-2">
            <h1 class="mb-0"><a href="/">WHOIS Lookup</a></h1>
            <button class="btn btn-sm btn-outline-secondary" id="darkModeToggle" title="Toggle dark mode">
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
        </ul>

        <div id="whoisResultPane"><div id="result"></div></div>
        <div id="dnsResultPane" style="display:none;"></div>

        <div id="actionButtons" class="mt-2 d-flex gap-2 flex-wrap" style="display:none !important;">
            <button class="btn btn-secondary btn-sm" id="toggleViewBtn">Show Raw Whois</button>
            <button class="btn btn-outline-secondary btn-sm" id="copyBtn"><i class="bi bi-clipboard"></i> Copy</button>
            <button class="btn btn-outline-secondary btn-sm" id="downloadBtn"><i class="bi bi-download"></i> Download</button>
        </div>

        <div id="bulkResults" class="accordion mt-3" style="display:none;"></div>
    </div>

    <!-- Footer -->
    <div class="footer">&copy; <?php echo htmlspecialchars("$copyrightYear $copyrightOwner"); ?>. All Rights Reserved</div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    document.addEventListener('DOMContentLoaded', function () {
        var CSRF = '<?php echo htmlspecialchars($csrfToken); ?>';
        var formattedResult = '';
        var rawWhoisText = '';
        var isRawView = false;
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
                return '<button class="btn btn-sm btn-outline-primary history-item" data-domain="' + x.domain + '">' + x.domain + '</button>';
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
        function triggerBulkLookup(domains) {
            showLoading(true);
            hideResults();
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
                            var badgeClass = data.availability === 'available' ? 'bg-success' : 'bg-info';
                            var badgeText = data.availability === 'available' ? 'Available' : 'Registered';
                            var regBtn = '';
                            if (data.availability === 'available') {
                                regBtn = ' <a href="https://store.mwservices.it/cart.php?a=add&domain=register&query=' + encodeURIComponent(domain) +
                                    '" target="_blank" class="btn btn-success btn-sm ms-2"><i class="bi bi-cart-plus me-1"></i>Register</a>';
                            }
                            var item = document.createElement('div');
                            item.className = 'accordion-item';
                            item.innerHTML =
                                '<h2 class="accordion-header"><button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#bulk-' + i + '">' +
                                domain + ' <span class="badge ' + badgeClass + ' ms-2">' + badgeText + '</span>' + regBtn +
                                '</button></h2>' +
                                '<div id="bulk-' + i + '" class="accordion-collapse collapse"><div class="accordion-body"><pre>' +
                                (data.whois || data.error || 'No data') + '</pre></div></div>';
                            acc.appendChild(item);
                        })
                        .catch(function () {})
                        .finally(function () { if (++done === domains.length) showLoading(false); });
                }, i * 1000);
            });
        }

        // ── Display results ──
        function displayResults(data) {
            // Availability badge
            var avBadge = document.getElementById('availabilityBadge');
            if (data.availability === 'available') {
                var regUrl = 'https://store.mwservices.it/cart.php?a=add&domain=register&query=' + encodeURIComponent(currentDomain);
                avBadge.innerHTML = '<div class="alert alert-success d-flex align-items-center justify-content-between flex-wrap gap-2">' +
                    '<div><i class="bi bi-check-circle-fill me-2"></i><strong>' + currentDomain + '</strong> appears to be available!</div>' +
                    '<a href="' + regUrl + '" target="_blank" class="btn btn-success btn-sm"><i class="bi bi-cart-plus me-1"></i>Register this domain</a></div>';
            } else {
                avBadge.innerHTML = '<div class="alert alert-info d-flex align-items-center"><i class="bi bi-info-circle-fill me-2"></i><strong>' + currentDomain + '</strong> is registered.</div>';
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

        // ── Helpers ──
        function showLoading(on) { document.getElementById('loadingSpinner').style.display = on ? '' : 'none'; }
        function hideResults() {
            ['availabilityBadge', 'dataSourceBadge', 'parsedFields', 'resultTabs', 'dnsResultPane', 'bulkResults'].forEach(function (id) {
                document.getElementById(id).style.display = 'none';
            });
            document.getElementById('whoisResultPane').style.display = '';
            document.getElementById('result').innerHTML = '';
            document.getElementById('actionButtons').style.cssText = 'display:none !important';
        }
        function showError(msg) { document.getElementById('result').innerHTML = '<div class="alert alert-danger"><i class="bi bi-exclamation-triangle-fill me-2"></i>' + msg + '</div>'; }
        function updateURL(d) { history.pushState(null, '', window.location.pathname + '?domain=' + encodeURIComponent(d)); }
    });
    </script>
</body>
</html>
