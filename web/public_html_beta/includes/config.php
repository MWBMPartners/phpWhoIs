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
    // Public DNS servers used for propagation checks.
    // Each entry has a unique sequential 'id', provider 'name' (may repeat),
    // 'ip', 'location', 'type', and 'enabled' toggle.
    // Types: 'standard' = unfiltered, 'security' = malware/threat blocking,
    //        'family' = adult content + parental control filtering.
    // Set 'enabled' to false to skip a resolver without removing it.
        'dns_resolvers' => [
            // ── Global / Anycast ──
            ['id' => 1,  'enabled' => true,  'name' => 'Google',         'ip' => '8.8.8.8',          'location' => 'Global',      'type' => 'standard'],
            ['id' => 2,  'enabled' => true,  'name' => 'Google',         'ip' => '8.8.4.4',          'location' => 'Global',      'type' => 'standard'],
            ['id' => 3,  'enabled' => true,  'name' => 'Cloudflare',     'ip' => '1.1.1.1',          'location' => 'Global',      'type' => 'standard'],
            ['id' => 4,  'enabled' => true,  'name' => 'Cloudflare',     'ip' => '1.0.0.1',          'location' => 'Global',      'type' => 'standard'],
            ['id' => 5,  'enabled' => true,  'name' => 'Quad9',          'ip' => '9.9.9.9',          'location' => 'Global',      'type' => 'standard'],
            ['id' => 6,  'enabled' => true,  'name' => 'Quad9',          'ip' => '149.112.112.112',  'location' => 'Global',      'type' => 'standard'],
            ['id' => 7,  'enabled' => true,  'name' => 'OpenDNS',        'ip' => '208.67.222.222',   'location' => 'Global',      'type' => 'standard'],
            ['id' => 8,  'enabled' => true,  'name' => 'OpenDNS',        'ip' => '208.67.220.220',   'location' => 'Global',      'type' => 'standard'],

            // ── North America ──
            ['id' => 9,  'enabled' => true,  'name' => 'Comodo Secure',  'ip' => '8.26.56.26',       'location' => 'US',          'type' => 'standard'],
            ['id' => 10, 'enabled' => true,  'name' => 'Neustar',        'ip' => '64.6.64.6',        'location' => 'US',          'type' => 'standard'],
            ['id' => 11, 'enabled' => true,  'name' => 'Neustar',        'ip' => '64.6.65.6',        'location' => 'US',          'type' => 'standard'],
            ['id' => 12, 'enabled' => true,  'name' => 'Level3',         'ip' => '4.2.2.1',          'location' => 'US',          'type' => 'standard'],
            ['id' => 13, 'enabled' => true,  'name' => 'Level3',         'ip' => '4.2.2.2',          'location' => 'US',          'type' => 'standard'],
            ['id' => 14, 'enabled' => true,  'name' => 'Verisign',       'ip' => '199.85.127.20',    'location' => 'US',          'type' => 'standard'],
            ['id' => 15, 'enabled' => true,  'name' => 'Norton CS',      'ip' => '199.85.126.20',    'location' => 'US',          'type' => 'standard'],
            ['id' => 16, 'enabled' => true,  'name' => 'SafeDNS',        'ip' => '195.46.39.39',     'location' => 'US',          'type' => 'standard'],
            ['id' => 17, 'enabled' => true,  'name' => 'CIRA Shield',    'ip' => '149.112.121.10',   'location' => 'Canada',      'type' => 'standard'],

            // ── Europe ──
            ['id' => 18, 'enabled' => true,  'name' => 'DNS.WATCH',      'ip' => '84.200.69.80',     'location' => 'Germany',     'type' => 'standard'],
            ['id' => 19, 'enabled' => true,  'name' => 'DNS.WATCH',      'ip' => '84.200.70.40',     'location' => 'Germany',     'type' => 'standard'],
            ['id' => 20, 'enabled' => true,  'name' => 'Freenom World',  'ip' => '80.80.80.80',      'location' => 'Netherlands', 'type' => 'standard'],
            ['id' => 21, 'enabled' => true,  'name' => 'Freenom World',  'ip' => '80.80.81.81',      'location' => 'Netherlands', 'type' => 'standard'],
            ['id' => 22, 'enabled' => true,  'name' => 'UncensoredDNS',  'ip' => '91.239.100.100',   'location' => 'Denmark',     'type' => 'standard'],
            ['id' => 23, 'enabled' => true,  'name' => 'Hetzner',        'ip' => '185.12.64.1',      'location' => 'Germany',     'type' => 'standard'],
            ['id' => 24, 'enabled' => true,  'name' => 'meerfarbig',     'ip' => '195.10.195.195',   'location' => 'Germany',     'type' => 'standard'],
            ['id' => 25, 'enabled' => true,  'name' => 'Foundation DNS', 'ip' => '37.235.1.174',     'location' => 'Switzerland', 'type' => 'standard'],
            ['id' => 26, 'enabled' => true,  'name' => 'Foundation DNS', 'ip' => '37.235.1.177',     'location' => 'Switzerland', 'type' => 'standard'],

            // ── Asia-Pacific ──
            ['id' => 27, 'enabled' => true,  'name' => 'Ali DNS',        'ip' => '223.5.5.5',        'location' => 'China',       'type' => 'standard'],
            ['id' => 28, 'enabled' => true,  'name' => 'Ali DNS',        'ip' => '223.6.6.6',        'location' => 'China',       'type' => 'standard'],
            ['id' => 29, 'enabled' => true,  'name' => 'Yandex',         'ip' => '77.88.8.8',        'location' => 'Russia',      'type' => 'standard'],
            ['id' => 30, 'enabled' => true,  'name' => 'Yandex',         'ip' => '77.88.8.1',        'location' => 'Russia',      'type' => 'standard'],
            ['id' => 31, 'enabled' => true,  'name' => 'HGC Global',     'ip' => '210.0.128.250',    'location' => 'Hong Kong',   'type' => 'standard'],
            ['id' => 32, 'enabled' => true,  'name' => 'HGC Global',     'ip' => '210.0.128.251',    'location' => 'Hong Kong',   'type' => 'standard'],
            ['id' => 33, 'enabled' => true,  'name' => 'TWNIC',          'ip' => '101.101.101.101',  'location' => 'Taiwan',      'type' => 'standard'],
            ['id' => 34, 'enabled' => true,  'name' => 'TWNIC',          'ip' => '101.102.103.104',  'location' => 'Taiwan',      'type' => 'standard'],
            ['id' => 35, 'enabled' => true,  'name' => 'SKB DNS',        'ip' => '210.220.163.82',   'location' => 'South Korea', 'type' => 'standard'],

            // ── South America ──
            ['id' => 36, 'enabled' => true,  'name' => 'Censurfridns',   'ip' => '89.233.43.71',     'location' => 'Brazil',      'type' => 'standard'],

            // ── Africa / Middle East ──
            ['id' => 37, 'enabled' => true,  'name' => 'Comss.one',      'ip' => '92.38.152.163',    'location' => 'UAE',         'type' => 'standard'],

            // ── Security — malware / threat blocking (disabled by default) ──
            ['id' => 38, 'enabled' => false, 'name' => 'Cloudflare',     'ip' => '1.1.1.2',          'location' => 'Global',      'type' => 'security'],
            ['id' => 39, 'enabled' => false, 'name' => 'Cloudflare',     'ip' => '1.0.0.2',          'location' => 'Global',      'type' => 'security'],
            ['id' => 40, 'enabled' => false, 'name' => 'AdGuard',        'ip' => '94.140.14.14',     'location' => 'Global',      'type' => 'security'],
            ['id' => 41, 'enabled' => false, 'name' => 'AdGuard',        'ip' => '94.140.15.15',     'location' => 'Global',      'type' => 'security'],
            ['id' => 42, 'enabled' => false, 'name' => 'CleanBrowsing',  'ip' => '185.228.168.9',    'location' => 'Global',      'type' => 'security'],
            ['id' => 43, 'enabled' => false, 'name' => 'CleanBrowsing',  'ip' => '185.228.169.9',    'location' => 'Global',      'type' => 'security'],
            ['id' => 44, 'enabled' => false, 'name' => 'Neustar',        'ip' => '156.154.70.2',     'location' => 'US',          'type' => 'security'],
            ['id' => 45, 'enabled' => false, 'name' => 'Neustar',        'ip' => '156.154.71.2',     'location' => 'US',          'type' => 'security'],
            ['id' => 46, 'enabled' => false, 'name' => 'Quad9',          'ip' => '9.9.9.11',         'location' => 'Global',      'type' => 'security'],
            ['id' => 47, 'enabled' => false, 'name' => 'Quad9',          'ip' => '149.112.112.11',   'location' => 'Global',      'type' => 'security'],
            ['id' => 48, 'enabled' => false, 'name' => 'Yandex',         'ip' => '77.88.8.88',       'location' => 'Russia',      'type' => 'security'],
            ['id' => 49, 'enabled' => false, 'name' => 'Yandex',         'ip' => '77.88.8.2',        'location' => 'Russia',      'type' => 'security'],

            // ── Family — parental control / adult content filtering (disabled by default) ──
            ['id' => 50, 'enabled' => false, 'name' => 'Cloudflare',     'ip' => '1.1.1.3',          'location' => 'Global',      'type' => 'family'],
            ['id' => 51, 'enabled' => false, 'name' => 'Cloudflare',     'ip' => '1.0.0.3',          'location' => 'Global',      'type' => 'family'],
            ['id' => 52, 'enabled' => false, 'name' => 'OpenDNS',        'ip' => '208.67.222.123',   'location' => 'Global',      'type' => 'family'],
            ['id' => 53, 'enabled' => false, 'name' => 'OpenDNS',        'ip' => '208.67.220.123',   'location' => 'Global',      'type' => 'family'],
            ['id' => 54, 'enabled' => false, 'name' => 'AdGuard',        'ip' => '94.140.14.15',     'location' => 'Global',      'type' => 'family'],
            ['id' => 55, 'enabled' => false, 'name' => 'AdGuard',        'ip' => '94.140.15.16',     'location' => 'Global',      'type' => 'family'],
            ['id' => 56, 'enabled' => false, 'name' => 'CleanBrowsing',  'ip' => '185.228.168.168',  'location' => 'Global',      'type' => 'family'],
            ['id' => 57, 'enabled' => false, 'name' => 'CleanBrowsing',  'ip' => '185.228.169.168',  'location' => 'Global',      'type' => 'family'],
            ['id' => 58, 'enabled' => false, 'name' => 'Neustar',        'ip' => '156.154.70.3',     'location' => 'US',          'type' => 'family'],
            ['id' => 59, 'enabled' => false, 'name' => 'Neustar',        'ip' => '156.154.71.3',     'location' => 'US',          'type' => 'family'],
            ['id' => 60, 'enabled' => false, 'name' => 'Yandex',         'ip' => '77.88.8.7',        'location' => 'Russia',      'type' => 'family'],
            ['id' => 61, 'enabled' => false, 'name' => 'Yandex',         'ip' => '77.88.8.3',        'location' => 'Russia',      'type' => 'family'],
        ],
];