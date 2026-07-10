<?php
/**
 * Application configuration.
 * Edit these values to customise the application behaviour.
 */

// ── Secret keys — loaded from the gitignored, non-web-accessible web/.auth/keys.php ──
// (a sibling of the web root; falls back to empty so integrations stay dormant if absent)
$authKeys = [];
$authKeysFile = dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . '.auth' . DIRECTORY_SEPARATOR . 'keys.php';
if (is_file($authKeysFile)) {
    $loadedAuthKeys = require $authKeysFile;
    if (is_array($loadedAuthKeys)) { $authKeys = $loadedAuthKeys; }
}

$config = [
    // ── Domain Registration Providers ──
    // List one or more registrars. When a domain is available:
    //   - Single provider:   shows a direct "Register" button
    //   - Multiple providers: shows a dropdown to choose registrar
    // Set to empty array [] to disable registration buttons entirely.
        'registrars' => [
            [
                'enabled'         => true,
                'name'            => 'MWservices',
                'url_template'    => 'https://store.mwservices.it/cart.php?a=add&domain=register&query={domain}',
                'open_in_new_tab' => true,
            ],
            [
                'enabled'         => true,
                'name'            => 'CloudFlare',
                'url_template'    => 'https://domains.cloudflare.com/?domain={domain}',
                'open_in_new_tab' => true,
            ],
            [
                'enabled'         => false,
                'name'            => 'Namecheap',
                'url_template'    => 'https://www.namecheap.com/domains/registration/results/?domain={domain}',
                'open_in_new_tab' => true,
            ],
            [
                'enabled'         => false,  // Disabled — won't appear in the UI
                'name'            => 'GoDaddy',
                'url_template'    => 'https://www.godaddy.com/domainsearch/find?domainToCheck={domain}',
                'open_in_new_tab' => true,
            ],
        ],

    // ── Enhanced Security Features (API keys) ──
    // API keys are NOT enumerated here. Every key defined in web/.auth/keys.php
    // is merged into $config automatically (see the bottom of this file), so to
    // add a NEW provider key you edit ONLY web/.auth/keys.php — never this file.
    // Integrations stay dormant while their key is empty/absent.
    // See web/.auth/keys.example.php for the supported keys + where to obtain each.

    // ── Website Screenshot ──
        // Show website preview thumbnails. Works without a key (basic/free tier);
        // set 'screenshot_api_key' in web/.auth/keys.php to unlock higher
        // resolution / rate limits / premium features.
            'screenshot_enabled' => true,

    // ── Portfolio ──
    // Show the Domain Portfolio link in the footer and history bar.
    // The link is only displayed when enabled here AND the user has watched
    // domains in their browser (localStorage). Set to false to hide it entirely.
        'portfolio_enabled' => true,

    // ── Privacy & Compliance ──
    // Mask personal contact info (email, phone, address) in displayed WHOIS results.
    // Useful for GDPR-conscious deployments. Does not affect the raw WHOIS data.
        'mask_whois_contacts' => false,

    // ── DNS Propagation Resolvers ──
    // Loaded from includes/dns_resolvers.php — edit that file to add/remove/toggle servers.
    // Types: 'standard' | 'security' (malware/threat) | 'family' (parental control).
        'dns_resolvers' => require __DIR__ . DIRECTORY_SEPARATOR . 'dns_resolvers.php',
];

// ── Merge secret keys from web/.auth/keys.php ──
// Every key defined in keys.php is folded into $config here, so adding a NEW
// provider key there requires NO change to this file. The union operator (+=)
// keeps the values already set above, so keys.php can only ADD secret keys — it
// can never override a core config key (registrars, dns_resolvers, toggles, …).
$config += $authKeys;
