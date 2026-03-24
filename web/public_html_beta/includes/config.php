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
    // 'ip', 'location', and 'enabled' toggle. Set 'enabled' to false to skip.
        'dns_resolvers' => [
            // ── Global / Anycast ──
            ['id' => 1,  'enabled' => true,  'name' => 'Google',         'ip' => '8.8.8.8',         'location' => 'Global'],
            ['id' => 2,  'enabled' => true,  'name' => 'Google',         'ip' => '8.8.4.4',         'location' => 'Global'],
            ['id' => 3,  'enabled' => true,  'name' => 'Cloudflare',    'ip' => '1.1.1.1',         'location' => 'Global'],
            ['id' => 4,  'enabled' => true,  'name' => 'Cloudflare',    'ip' => '1.0.0.1',         'location' => 'Global'],
            ['id' => 5,  'enabled' => true,  'name' => 'Quad9',         'ip' => '9.9.9.9',         'location' => 'Global'],
            ['id' => 6,  'enabled' => true,  'name' => 'Quad9',         'ip' => '149.112.112.112', 'location' => 'Global'],
            ['id' => 7,  'enabled' => true,  'name' => 'OpenDNS',       'ip' => '208.67.222.222',  'location' => 'Global'],
            ['id' => 8,  'enabled' => true,  'name' => 'OpenDNS',       'ip' => '208.67.220.220',  'location' => 'Global'],

            // ── North America ──
            ['id' => 9,  'enabled' => true,  'name' => 'Comodo Secure', 'ip' => '8.26.56.26',      'location' => 'US'],
            ['id' => 10, 'enabled' => true,  'name' => 'Neustar',       'ip' => '64.6.64.6',       'location' => 'US'],
            ['id' => 11, 'enabled' => true,  'name' => 'Neustar',       'ip' => '64.6.65.6',       'location' => 'US'],
            ['id' => 12, 'enabled' => true,  'name' => 'Level3',        'ip' => '4.2.2.1',         'location' => 'US'],
            ['id' => 13, 'enabled' => true,  'name' => 'Level3',        'ip' => '4.2.2.2',         'location' => 'US'],
            ['id' => 14, 'enabled' => true,  'name' => 'Verisign',      'ip' => '199.85.127.20',   'location' => 'US'],
            ['id' => 15, 'enabled' => true,  'name' => 'Norton CS',     'ip' => '199.85.126.20',   'location' => 'US'],
            ['id' => 16, 'enabled' => true,  'name' => 'SafeDNS',       'ip' => '195.46.39.39',    'location' => 'US'],
            ['id' => 17, 'enabled' => true,  'name' => 'CIRA Shield',   'ip' => '149.112.121.10',  'location' => 'Canada'],

            // ── Europe ──
            ['id' => 18, 'enabled' => true,  'name' => 'DNS.WATCH',     'ip' => '84.200.69.80',    'location' => 'Germany'],
            ['id' => 19, 'enabled' => true,  'name' => 'DNS.WATCH',     'ip' => '84.200.70.40',    'location' => 'Germany'],
            ['id' => 20, 'enabled' => true,  'name' => 'Freenom World', 'ip' => '80.80.80.80',     'location' => 'Netherlands'],
            ['id' => 21, 'enabled' => true,  'name' => 'Freenom World', 'ip' => '80.80.81.81',     'location' => 'Netherlands'],
            ['id' => 22, 'enabled' => true,  'name' => 'UncensoredDNS', 'ip' => '91.239.100.100',  'location' => 'Denmark'],
            ['id' => 23, 'enabled' => true,  'name' => 'Hetzner',       'ip' => '185.12.64.1',     'location' => 'Germany'],
            ['id' => 24, 'enabled' => true,  'name' => 'meerfarbig',    'ip' => '195.10.195.195',  'location' => 'Germany'],
            ['id' => 25, 'enabled' => true,  'name' => 'Foundation DNS','ip' => '37.235.1.174',    'location' => 'Switzerland'],
            ['id' => 26, 'enabled' => true,  'name' => 'Foundation DNS','ip' => '37.235.1.177',    'location' => 'Switzerland'],

            // ── Asia-Pacific ──
            ['id' => 27, 'enabled' => true,  'name' => 'Ali DNS',       'ip' => '223.5.5.5',       'location' => 'China'],
            ['id' => 28, 'enabled' => true,  'name' => 'Ali DNS',       'ip' => '223.6.6.6',       'location' => 'China'],
            ['id' => 29, 'enabled' => true,  'name' => 'Yandex',        'ip' => '77.88.8.8',       'location' => 'Russia'],
            ['id' => 30, 'enabled' => true,  'name' => 'Yandex',        'ip' => '77.88.8.1',       'location' => 'Russia'],
            ['id' => 31, 'enabled' => true,  'name' => 'HGC Global',    'ip' => '210.0.128.250',   'location' => 'Hong Kong'],
            ['id' => 32, 'enabled' => true,  'name' => 'HGC Global',    'ip' => '210.0.128.251',   'location' => 'Hong Kong'],
            ['id' => 33, 'enabled' => true,  'name' => 'TWNIC',         'ip' => '101.101.101.101', 'location' => 'Taiwan'],
            ['id' => 34, 'enabled' => true,  'name' => 'TWNIC',         'ip' => '101.102.103.104', 'location' => 'Taiwan'],
            ['id' => 35, 'enabled' => true,  'name' => 'SKB DNS',       'ip' => '210.220.163.82',  'location' => 'South Korea'],

            // ── South America ──
            ['id' => 36, 'enabled' => true,  'name' => 'Censurfridns',  'ip' => '89.233.43.71',    'location' => 'Brazil'],

            // ── Africa / Middle East ──
            ['id' => 37, 'enabled' => true,  'name' => 'Comss.one',     'ip' => '92.38.152.163',   'location' => 'UAE'],

            // ── Parental Control / Filtered (disabled by default) ──
            // Cloudflare for Families — malware blocking
            ['id' => 38, 'enabled' => false, 'name' => 'Cloudflare Malware',    'ip' => '1.1.1.2',       'location' => 'Global'],
            ['id' => 39, 'enabled' => false, 'name' => 'Cloudflare Malware',    'ip' => '1.0.0.2',       'location' => 'Global'],
            // Cloudflare for Families — malware + adult content blocking
            ['id' => 40, 'enabled' => false, 'name' => 'Cloudflare Family',     'ip' => '1.1.1.3',       'location' => 'Global'],
            ['id' => 41, 'enabled' => false, 'name' => 'Cloudflare Family',     'ip' => '1.0.0.3',       'location' => 'Global'],
            // OpenDNS FamilyShield — pre-configured adult content blocking
            ['id' => 42, 'enabled' => false, 'name' => 'OpenDNS Family',        'ip' => '208.67.222.123','location' => 'Global'],
            ['id' => 43, 'enabled' => false, 'name' => 'OpenDNS Family',        'ip' => '208.67.220.123','location' => 'Global'],
            // AdGuard DNS — ad + tracker blocking
            ['id' => 44, 'enabled' => false, 'name' => 'AdGuard',               'ip' => '94.140.14.14',  'location' => 'Global'],
            ['id' => 45, 'enabled' => false, 'name' => 'AdGuard',               'ip' => '94.140.15.15',  'location' => 'Global'],
            // AdGuard Family — ad + tracker + adult content blocking
            ['id' => 46, 'enabled' => false, 'name' => 'AdGuard Family',        'ip' => '94.140.14.15',  'location' => 'Global'],
            ['id' => 47, 'enabled' => false, 'name' => 'AdGuard Family',        'ip' => '94.140.15.16',  'location' => 'Global'],
            // CleanBrowsing — security filter (malware + phishing)
            ['id' => 48, 'enabled' => false, 'name' => 'CleanBrowsing Security','ip' => '185.228.168.9', 'location' => 'Global'],
            ['id' => 49, 'enabled' => false, 'name' => 'CleanBrowsing Security','ip' => '185.228.169.9', 'location' => 'Global'],
            // CleanBrowsing — adult content filter
            ['id' => 50, 'enabled' => false, 'name' => 'CleanBrowsing Adult',   'ip' => '185.228.168.10','location' => 'Global'],
            ['id' => 51, 'enabled' => false, 'name' => 'CleanBrowsing Adult',   'ip' => '185.228.169.11','location' => 'Global'],
            // CleanBrowsing — family filter (strictest)
            ['id' => 52, 'enabled' => false, 'name' => 'CleanBrowsing Family',  'ip' => '185.228.168.168','location' => 'Global'],
            ['id' => 53, 'enabled' => false, 'name' => 'CleanBrowsing Family',  'ip' => '185.228.169.168','location' => 'Global'],
            // Neustar UltraDNS — threat protection
            ['id' => 54, 'enabled' => false, 'name' => 'Neustar Threat',        'ip' => '156.154.70.2',  'location' => 'US'],
            ['id' => 55, 'enabled' => false, 'name' => 'Neustar Threat',        'ip' => '156.154.71.2',  'location' => 'US'],
            // Neustar UltraDNS — family secure (threat + adult content)
            ['id' => 56, 'enabled' => false, 'name' => 'Neustar Family',        'ip' => '156.154.70.3',  'location' => 'US'],
            ['id' => 57, 'enabled' => false, 'name' => 'Neustar Family',        'ip' => '156.154.71.3',  'location' => 'US'],
            // Quad9 — threat blocking (ECS enabled)
            ['id' => 58, 'enabled' => false, 'name' => 'Quad9 Threat',          'ip' => '9.9.9.11',      'location' => 'Global'],
            ['id' => 59, 'enabled' => false, 'name' => 'Quad9 Threat',          'ip' => '149.112.112.11','location' => 'Global'],
            // Yandex Family — adult content blocking
            ['id' => 60, 'enabled' => false, 'name' => 'Yandex Family',         'ip' => '77.88.8.7',     'location' => 'Russia'],
            ['id' => 61, 'enabled' => false, 'name' => 'Yandex Family',         'ip' => '77.88.8.3',     'location' => 'Russia'],
            // Yandex Safe — malware + phishing blocking
            ['id' => 62, 'enabled' => false, 'name' => 'Yandex Safe',           'ip' => '77.88.8.88',    'location' => 'Russia'],
            ['id' => 63, 'enabled' => false, 'name' => 'Yandex Safe',           'ip' => '77.88.8.2',     'location' => 'Russia'],
        ],
];