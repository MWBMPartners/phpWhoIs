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
    // Set 'enabled' to false to skip a resolver without removing it.
    // Location is informational — shown in the UI to indicate geographic spread.
        'dns_resolvers' => [
            // ── Global / Anycast ──
            ['enabled' => true,  'name' => 'Google',           'ip' => '8.8.8.8',         'location' => 'Global'],
            ['enabled' => true,  'name' => 'Google (2)',       'ip' => '8.8.4.4',         'location' => 'Global'],
            ['enabled' => true,  'name' => 'Cloudflare',      'ip' => '1.1.1.1',         'location' => 'Global'],
            ['enabled' => true,  'name' => 'Cloudflare (2)',  'ip' => '1.0.0.1',         'location' => 'Global'],
            ['enabled' => true,  'name' => 'Quad9',           'ip' => '9.9.9.9',         'location' => 'Global'],
            ['enabled' => true,  'name' => 'Quad9 (2)',       'ip' => '149.112.112.112', 'location' => 'Global'],
            ['enabled' => true,  'name' => 'OpenDNS',         'ip' => '208.67.222.222',  'location' => 'Global'],
            ['enabled' => true,  'name' => 'OpenDNS (2)',     'ip' => '208.67.220.220',  'location' => 'Global'],

            // ── North America ──
            ['enabled' => true,  'name' => 'Comodo Secure',   'ip' => '8.26.56.26',      'location' => 'US'],
            ['enabled' => true,  'name' => 'Neustar',         'ip' => '64.6.64.6',       'location' => 'US'],
            ['enabled' => true,  'name' => 'Neustar (2)',     'ip' => '64.6.65.6',       'location' => 'US'],
            ['enabled' => true,  'name' => 'Level3',          'ip' => '4.2.2.1',         'location' => 'US'],
            ['enabled' => true,  'name' => 'Level3 (2)',      'ip' => '4.2.2.2',         'location' => 'US'],
            ['enabled' => true,  'name' => 'Verisign',        'ip' => '199.85.127.20',   'location' => 'US'],
            ['enabled' => true,  'name' => 'Norton CS',       'ip' => '199.85.126.20',   'location' => 'US'],
            ['enabled' => true,  'name' => 'SafeDNS',         'ip' => '195.46.39.39',    'location' => 'US'],
            ['enabled' => true,  'name' => 'CIRA Shield',     'ip' => '149.112.121.10',  'location' => 'Canada'],

            // ── Europe ──
            ['enabled' => true,  'name' => 'DNS.WATCH',       'ip' => '84.200.69.80',    'location' => 'Germany'],
            ['enabled' => true,  'name' => 'DNS.WATCH (2)',   'ip' => '84.200.70.40',    'location' => 'Germany'],
            ['enabled' => true,  'name' => 'Freenom World',   'ip' => '80.80.80.80',     'location' => 'Netherlands'],
            ['enabled' => true,  'name' => 'Freenom (2)',     'ip' => '80.80.81.81',     'location' => 'Netherlands'],
            ['enabled' => true,  'name' => 'UncensoredDNS',   'ip' => '91.239.100.100',  'location' => 'Denmark'],
            ['enabled' => true,  'name' => 'Hetzner',         'ip' => '185.12.64.1',     'location' => 'Germany'],
            ['enabled' => true,  'name' => 'meerfarbig',      'ip' => '195.10.195.195',  'location' => 'Germany'],
            ['enabled' => true,  'name' => 'Foundation DNS',  'ip' => '37.235.1.174',    'location' => 'Switzerland'],
            ['enabled' => true,  'name' => 'Foundation (2)',  'ip' => '37.235.1.177',    'location' => 'Switzerland'],

            // ── Asia-Pacific ──
            ['enabled' => true,  'name' => 'Ali DNS',         'ip' => '223.5.5.5',       'location' => 'China'],
            ['enabled' => true,  'name' => 'Ali DNS (2)',     'ip' => '223.6.6.6',       'location' => 'China'],
            ['enabled' => true,  'name' => 'Yandex',          'ip' => '77.88.8.8',       'location' => 'Russia'],
            ['enabled' => true,  'name' => 'Yandex (2)',      'ip' => '77.88.8.1',       'location' => 'Russia'],
            ['enabled' => true,  'name' => 'HGC Global',      'ip' => '210.0.128.250',   'location' => 'Hong Kong'],
            ['enabled' => true,  'name' => 'HGC Global (2)', 'ip' => '210.0.128.251',   'location' => 'Hong Kong'],
            ['enabled' => true,  'name' => 'TWNIC',           'ip' => '101.101.101.101', 'location' => 'Taiwan'],
            ['enabled' => true,  'name' => 'TWNIC (2)',       'ip' => '101.102.103.104', 'location' => 'Taiwan'],
            ['enabled' => true,  'name' => 'SKB DNS',         'ip' => '210.220.163.82',  'location' => 'South Korea'],

            // ── South America ──
            ['enabled' => true,  'name' => 'Censurfridns',    'ip' => '89.233.43.71',    'location' => 'Brazil'],

            // ── Africa / Middle East ──
            ['enabled' => true,  'name' => 'Comss.one',       'ip' => '92.38.152.163',   'location' => 'UAE'],

            // ── Filtered / Family-safe (disabled by default) ──
            ['enabled' => false, 'name' => 'CleanBrowsing',   'ip' => '185.228.168.9',   'location' => 'Global'],
            ['enabled' => false, 'name' => 'AdGuard',         'ip' => '94.140.14.14',    'location' => 'Global'],
            ['enabled' => false, 'name' => 'AdGuard (2)',     'ip' => '94.140.15.15',    'location' => 'Global'],
            ['enabled' => false, 'name' => 'OpenDNS Family',  'ip' => '208.67.222.123',  'location' => 'Global'],
            ['enabled' => false, 'name' => 'Neustar Family',  'ip' => '156.154.70.3',    'location' => 'US'],
        ],
];