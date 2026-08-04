<?php
/**
 * mwWhoIs - API Documentation (Swagger UI)
 *
 * Access restricted to logged-in users with a Developer account (Issue #172).
 * Until the user account system (#163) is implemented, this page is
 * accessible to everyone. Once #163 lands, uncomment the access gate below.
 */

// ─── Session (needed for access control) ───
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'session_config.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'asset_version.php';

// ─── Access gate: logged-in developer accounts only (Issue #172) ───
// Uncomment the block below once the user account system (#163) is live:
// if (empty($_SESSION['logged_in']) || empty($_SESSION['is_developer'])) {
//     http_response_code(403);
//     header('Location: /');
//     exit;
// }

// ─── App version info ───
if (file_exists(__DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php')) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'infoAppVer.php';
}
header_remove('X-Powered-By');
if (isset($app["Application"]["Name"]) && $app["Application"]["Name"]) {
    $poweredBy = $app["Application"]["Name"];
    if (isset($app["Application"]["Version"]["Number"]) && $app["Application"]["Version"]["Number"]) {
        $poweredBy .= '/' . $app["Application"]["Version"]["Number"];
    }
    header('X-Powered-By: ' . $poweredBy);
}

$appName = isset($app["Application"]["Name"]) && $app["Application"]["Name"]
    ? $app["Application"]["Name"]
    : 'mwWhoIs';
?>
<!DOCTYPE html>
<html lang="en" data-bs-theme="light">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — API Documentation</title>
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.13.1/font/bootstrap-icons.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <link rel="stylesheet" href="assets/css/style.css?v=<?php echo assetVersion(__DIR__ . DIRECTORY_SEPARATOR . 'assets' . DIRECTORY_SEPARATOR . 'css' . DIRECTORY_SEPARATOR . 'style.css'); ?>">
    <style>
        /* Swagger UI overrides to match site theme */
        .swagger-ui .topbar { display: none !important; }
        .swagger-ui { font-family: inherit; }

        /* Light mode (default) */
        .swagger-ui .opblock-tag,
        .swagger-ui .opblock-summary-description,
        .swagger-ui .response-col_description__inner p,
        .swagger-ui table thead tr th,
        .swagger-ui .parameter__name,
        .swagger-ui .parameter__type,
        .swagger-ui .model-title,
        .swagger-ui .model { color: inherit; }

        /* Dark mode overrides */
        [data-bs-theme="dark"] .swagger-ui { color: #dee2e6; }
        [data-bs-theme="dark"] .swagger-ui .info .title,
        [data-bs-theme="dark"] .swagger-ui .info p,
        [data-bs-theme="dark"] .swagger-ui .info li,
        [data-bs-theme="dark"] .swagger-ui .info a,
        [data-bs-theme="dark"] .swagger-ui .info h2,
        [data-bs-theme="dark"] .swagger-ui .info h3,
        [data-bs-theme="dark"] .swagger-ui .info h4,
        [data-bs-theme="dark"] .swagger-ui .opblock-tag,
        [data-bs-theme="dark"] .swagger-ui .opblock-summary-description,
        [data-bs-theme="dark"] .swagger-ui .opblock-description-wrapper p,
        [data-bs-theme="dark"] .swagger-ui .response-col_description__inner p,
        [data-bs-theme="dark"] .swagger-ui table thead tr th,
        [data-bs-theme="dark"] .swagger-ui .parameter__name,
        [data-bs-theme="dark"] .swagger-ui .parameter__type,
        [data-bs-theme="dark"] .swagger-ui .model-title,
        [data-bs-theme="dark"] .swagger-ui .model,
        [data-bs-theme="dark"] .swagger-ui .responses-inner h4,
        [data-bs-theme="dark"] .swagger-ui .responses-inner h5,
        [data-bs-theme="dark"] .swagger-ui .response-col_status,
        [data-bs-theme="dark"] .swagger-ui label,
        [data-bs-theme="dark"] .swagger-ui .btn { color: #dee2e6; }

        [data-bs-theme="dark"] .swagger-ui .opblock .opblock-summary { border-color: #495057; }
        [data-bs-theme="dark"] .swagger-ui .opblock { background: #1a1d20; border-color: #495057; }
        [data-bs-theme="dark"] .swagger-ui .opblock .opblock-section-header { background: #2b3035; }
        [data-bs-theme="dark"] .swagger-ui section.models { border-color: #495057; }
        [data-bs-theme="dark"] .swagger-ui section.models .model-container { background: #1a1d20; }
        [data-bs-theme="dark"] .swagger-ui .model-box { background: #2b3035; }
        [data-bs-theme="dark"] .swagger-ui table tbody tr td { color: #dee2e6; }
        [data-bs-theme="dark"] .swagger-ui .scheme-container { background: #1a1d20; }
        [data-bs-theme="dark"] .swagger-ui select { background: #2b3035; color: #dee2e6; border-color: #495057; }
        [data-bs-theme="dark"] .swagger-ui input[type=text] { background: #2b3035; color: #dee2e6; border-color: #495057; }
        [data-bs-theme="dark"] .swagger-ui textarea { background: #2b3035; color: #dee2e6; border-color: #495057; }

        /* Colourblind overrides */
        [data-theme="colourblind"] .swagger-ui .opblock.opblock-post { background: rgba(0, 119, 187, 0.08); border-color: #0077BB; }
        [data-theme="colourblind"] .swagger-ui .opblock.opblock-post .opblock-summary { border-color: #0077BB; }
        [data-theme="colourblind"] .swagger-ui .opblock.opblock-get { background: rgba(0, 153, 136, 0.08); border-color: #009988; }
        [data-theme="colourblind"] .swagger-ui .opblock.opblock-get .opblock-summary { border-color: #009988; }

        /* Layout */
        .docs-header {
            padding: 15px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .docs-header h1 { font-size: 1.2rem; font-weight: 600; margin: 0; }
        .docs-header h1 a { color: inherit; text-decoration: none; }
        .docs-header h1 img { height: 32px; vertical-align: middle; margin-right: 8px; }
        .docs-body { padding: 0 20px 80px; }
    </style>
</head>
<body>
    <header class="docs-header header-form">
        <h1>
            <a href="/">
                <img src="assets/images/logo-notext.svg" alt="" aria-hidden="true"><?php echo htmlspecialchars($appName); ?>
            </a>
            <small class="text-muted" style="font-weight: 400; font-size: 0.8em;">— API Documentation</small>
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
    </header>

    <div class="subpage-content">
        <div class="docs-body">
            <div id="swagger-ui"></div>
        </div>
    </div>

    <?php require __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'footer.php'; ?>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.8/dist/js/bootstrap.bundle.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        // ── Theme (synced with main site via localStorage) ──
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

        // ── Swagger UI ──
        SwaggerUIBundle({
            url: 'assets/api/openapi.yaml',
            dom_id: '#swagger-ui',
            deepLinking: true,
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: 'BaseLayout'
        });
    </script>
</body>
</html>
