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

    // ── Enhanced Security Features ──
    // These features activate automatically when a valid API key is provided.
    // Leave empty ('') or null to disable. No need to comment out.

        // Google Safe Browsing — checks domains against Google's malware/phishing database
        // Get a key from https://console.cloud.google.com/apis/api/safebrowsing.googleapis.com
            'safe_browsing_api_key' => '',

        // VirusTotal — domain reputation scores and antivirus verdicts
        // Get a free key from https://www.virustotal.com/gui/my-apikey
            'virustotal_api_key' => '',

        // Have I Been Pwned — data breach information for domains
        // Get a key from https://haveibeenpwned.com/API/Key
            'hibp_api_key' => '',

        // AbuseIPDB — IP reputation and abuse reports
        // Get a free key from https://www.abuseipdb.com/api
            'abuseipdb_api_key' => '',

        // Shodan — exposed services/ports on resolved IP
        // Get a free key from https://account.shodan.io/
            'shodan_api_key' => '',

        // PhishTank — known phishing URL database
        // Get a free key from https://www.phishtank.com/api_info.php
            'phishtank_api_key' => '',

    // ── Website Screenshot ──
        // Set 'screenshot_enabled' to true to show website preview thumbnails.
        // Works without an API key (basic/free tier). Provide an API key to
        // unlock higher resolution, rate limits, or premium features.
        // Leave 'screenshot_api_key' empty ('') for basic usage.
            'screenshot_enabled' => true,
            'screenshot_api_key' => '',

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
