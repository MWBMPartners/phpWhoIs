<?php
/**
 * mwWhoIs — Domain Portfolio Dashboard (Issue #141)
 * Client-side page using localStorage watch list data.
 */

if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}
header_remove('X-Powered-By');
$appName = isset($app["Application"]["Name"]) && $app["Application"]["Name"] ? $app["Application"]["Name"] : 'WHOIS Lookup';
$poweredBy = $appName;
if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]) {
    $poweredBy .= '/' . $app["Application"]["Version"]["Number"];
}
header('X-Powered-By: ' . $poweredBy);
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — Domain Portfolio</title>
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
                <small class="text-muted" style="font-weight: 400; font-size: 0.8em;">— Domain Portfolio</small>
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
        <div class="container py-4" style="max-width: 900px;">
            <div id="portfolioContent">
                <p class="text-muted">Loading watched domains...</p>
            </div>
        </div>
    </div>

    <?php require __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'footer.php'; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script>
    // Theme
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
        themeIcon.className = ({ auto: 'bi bi-circle-half', light: 'bi bi-sun-fill', dark: 'bi bi-moon-fill', colourblind: 'bi bi-eye-fill' })[t] || 'bi bi-circle-half';
        document.querySelectorAll('[data-theme-value]').forEach(function (item) { item.classList.toggle('active', item.dataset.themeValue === t); });
    }

    // Portfolio
    var list = [];
    try { list = JSON.parse(localStorage.getItem('whoisWatchList') || '[]'); } catch(e) {}
    var scores = {};
    try { scores = JSON.parse(localStorage.getItem('securityScoreHistory') || '{}'); } catch(e) {}

    var el = document.getElementById('portfolioContent');
    if (!list.length) {
        el.innerHTML = '<div class="text-center py-5"><i class="bi bi-collection" style="font-size:3rem;opacity:0.15;"></i><p class="mt-3 text-muted">No watched domains. Use the <i class="bi bi-eye"></i> button on lookup results to add domains.</p></div>';
    } else {
        var html = '<div class="table-responsive"><table class="table table-sm table-hover"><thead><tr><th>Domain</th><th>Expiry</th><th>Days Left</th><th>Security</th><th>Added</th><th></th></tr></thead><tbody>';
        list.forEach(function (w, idx) {
            var exp = w.expiry ? new Date(w.expiry) : null;
            var days = exp ? Math.ceil((exp - new Date()) / (1000*60*60*24)) : null;
            var daysClass = days !== null ? (days <= 30 ? 'text-danger fw-bold' : (days <= 90 ? 'text-warning' : '')) : '';
            var lastScore = scores[w.domain] && scores[w.domain].length ? scores[w.domain][scores[w.domain].length - 1] : null;
            var scoreHtml = lastScore ? '<span class="badge bg-' + (lastScore.grade <= 'B' ? 'success' : (lastScore.grade <= 'D' ? 'warning' : 'danger')) + '">' + lastScore.grade + '</span>' : '<span class="text-muted">—</span>';
            var added = w.added ? new Date(w.added).toLocaleDateString() : '—';

            html += '<tr><td><a href="/?domain=' + encodeURIComponent(w.domain) + '">' + w.domain + '</a></td>';
            html += '<td>' + (exp ? exp.toLocaleDateString() : '—') + '</td>';
            html += '<td class="' + daysClass + '">' + (days !== null ? days : '—') + '</td>';
            html += '<td>' + scoreHtml + '</td>';
            html += '<td class="text-muted small">' + added + '</td>';
            html += '<td><button class="btn btn-sm btn-outline-danger remove-btn" data-idx="' + idx + '" title="Remove"><i class="bi bi-x"></i></button></td></tr>';
        });
        html += '</tbody></table></div>';
        el.innerHTML = html;

        el.querySelectorAll('.remove-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                list.splice(parseInt(this.dataset.idx), 1);
                localStorage.setItem('whoisWatchList', JSON.stringify(list));
                location.reload();
            });
        });
    }
    </script>
</body>
</html>
