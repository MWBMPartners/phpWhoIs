<?php
/**
 * Application configuration.
 * Edit these values to customise the application behaviour.
 */

$config = [

    // Domain registration provider (primary — shown as main CTA button)
    'registration' => [
        // Set to false to hide the "Register this domain" button entirely
        'enabled' => true,

        // URL template — {domain} will be replaced with the searched domain name
        'url_template' => 'https://store.mwservices.it/cart.php?a=add&domain=register&query={domain}',

        // Button text shown to the user
        'button_text' => 'Register this domain',

        // Open the registration link in a new browser tab
        'open_in_new_tab' => true,
    ],

    // Additional registrar affiliates (Issue #63)
    // Each entry adds an alternative registration link when a domain is available.
    // 'affiliate_registrars' => [
    //     [
    //         'name'          => 'Namecheap',
    //         'url_template'  => 'https://www.namecheap.com/domains/registration/results/?domain={domain}',
    //         'open_in_new_tab' => true,
    //     ],
    //     [
    //         'name'          => 'GoDaddy',
    //         'url_template'  => 'https://www.godaddy.com/domainsearch/find?domainToCheck={domain}',
    //         'open_in_new_tab' => true,
    //     ],
    // ],

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
