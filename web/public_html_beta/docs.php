<?php
/**
 * mwWhoIs - API Documentation (Swagger UI)
 */

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
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($appName); ?> — API Documentation</title>
    <link rel="icon" type="image/svg+xml" href="assets/images/favicon.svg">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
    <style>
        html { box-sizing: border-box; overflow-y: scroll; }
        *, *::before, *::after { box-sizing: inherit; }
        body { margin: 0; background: #fafafa; }
        .topbar { display: none !important; }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
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
