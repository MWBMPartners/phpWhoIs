<?php
/**
 * Application configuration.
 * Edit these values to customise the application behaviour.
 */

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
        // Uncomment to add more providers:
        // [
        //     'enabled'         => true,
        //     'name'            => 'Namecheap',
        //     'url_template'    => 'https://www.namecheap.com/domains/registration/results/?domain={domain}',
        //     'open_in_new_tab' => true,
        // ],
        // [
        //     'enabled'         => false,  // Disabled — won't appear in the UI
        //     'name'            => 'GoDaddy',
        //     'url_template'    => 'https://www.godaddy.com/domainsearch/find?domainToCheck={domain}',
        //     'open_in_new_tab' => true,
        // ],
    ],

    // Google Safe Browsing API (Issue #52)
    // Get a key from https://console.cloud.google.com/apis/api/safebrowsing.googleapis.com
    // 'safe_browsing_api_key' => '',

    // VirusTotal API (Issue #53)
    // Get a free key from https://www.virustotal.com/gui/my-apikey
    // 'virustotal_api_key' => '',

    // Have I Been Pwned API (Issue #65)
    // Get a key from https://haveibeenpwned.com/API/Key
    // 'hibp_api_key' => '',

    // Website screenshot API (Issue #55)
    // Uses the free site-shot.com API — no key required for basic usage.
    // Set to true to enable thumbnail screenshots on lookup results.
    'screenshot_enabled' => true,
];
