<?php
/**
 * DNS Propagation Resolvers
 *
 * Public DNS servers used for propagation checks. Loaded by config.php.
 *
 * Each entry:
 *   id           Unique sequential identifier
 *   enabled      true/false — set false to skip without removing
 *   name         Provider name (may repeat across entries)
 *   ip           IPv4 address
 *   country_code ISO 3166-1 alpha-2 code (used for flag display), or 'GLOBAL'
 *   location     Human-readable location label
 *   type         'standard' | 'security' (malware/threat) | 'family' (parental control)
 *
 * Sort order:
 *   1. GLOBAL entries first, then alphabetically by location
 *   2. Within each location: alphabetically by resolver name
 *   3. Within each name: by type (standard → security → family)
 *
 * Sources:
 *   https://public-dns.info/
 *   https://github.com/pingproxies/public-dns-directory
 *   https://gist.github.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5
 *   https://blog.cloudflare.com/introducing-1-1-1-1-for-families/
 */

return [

    // ── Global ──
    ['id' => 59, 'enabled' => false, 'name' => 'CleanBrowsing',   'ip' => '185.228.168.9',    'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'security'],
    ['id' => 60, 'enabled' => false, 'name' => 'CleanBrowsing',   'ip' => '185.228.169.9',    'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'security'],
    ['id' => 73, 'enabled' => false, 'name' => 'CleanBrowsing',   'ip' => '185.228.168.168',  'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'family'],
    ['id' => 74, 'enabled' => false, 'name' => 'CleanBrowsing',   'ip' => '185.228.169.168',  'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'family'],
    ['id' => 3,  'enabled' => true,  'name' => 'Cloudflare',      'ip' => '1.0.0.1',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 4,  'enabled' => true,  'name' => 'Cloudflare',      'ip' => '1.1.1.1',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 55, 'enabled' => false, 'name' => 'Cloudflare',      'ip' => '1.0.0.2',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'security'],
    ['id' => 56, 'enabled' => false, 'name' => 'Cloudflare',      'ip' => '1.1.1.2',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'security'],
    ['id' => 67, 'enabled' => false, 'name' => 'Cloudflare',      'ip' => '1.0.0.3',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'family'],
    ['id' => 68, 'enabled' => false, 'name' => 'Cloudflare',      'ip' => '1.1.1.3',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'family'],
    ['id' => 9,  'enabled' => true,  'name' => 'DNS.SB',          'ip' => '185.222.222.222',  'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 10, 'enabled' => true,  'name' => 'DNS.SB',          'ip' => '45.11.45.11',      'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 1,  'enabled' => true,  'name' => 'Google',          'ip' => '8.8.4.4',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 2,  'enabled' => true,  'name' => 'Google',          'ip' => '8.8.8.8',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 7,  'enabled' => true,  'name' => 'OpenDNS',         'ip' => '208.67.220.220',   'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 8,  'enabled' => true,  'name' => 'OpenDNS',         'ip' => '208.67.222.222',   'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 69, 'enabled' => false, 'name' => 'OpenDNS',         'ip' => '208.67.220.123',   'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'family'],
    ['id' => 70, 'enabled' => false, 'name' => 'OpenDNS',         'ip' => '208.67.222.123',   'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'family'],
    ['id' => 5,  'enabled' => true,  'name' => 'Quad9',           'ip' => '149.112.112.112',  'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 6,  'enabled' => true,  'name' => 'Quad9',           'ip' => '9.9.9.9',          'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'standard'],
    ['id' => 63, 'enabled' => false, 'name' => 'Quad9',           'ip' => '149.112.112.11',   'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'security'],
    ['id' => 64, 'enabled' => false, 'name' => 'Quad9',           'ip' => '9.9.9.11',         'country_code' => 'GLOBAL', 'location' => 'Global',       'type' => 'security'],

    // ── Brazil ──
    ['id' => 53, 'enabled' => true,  'name' => 'Censurfridns',    'ip' => '89.233.43.71',     'country_code' => 'BR',     'location' => 'Brazil',       'type' => 'standard'],

    // ── Canada ──
    ['id' => 21, 'enabled' => true,  'name' => 'CIRA Shield',     'ip' => '149.112.121.10',   'country_code' => 'CA',     'location' => 'Canada',       'type' => 'standard'],
    ['id' => 22, 'enabled' => true,  'name' => 'CIRA Shield',     'ip' => '149.112.122.10',   'country_code' => 'CA',     'location' => 'Canada',       'type' => 'standard'],

    // ── China ──
    ['id' => 41, 'enabled' => true,  'name' => '114DNS',          'ip' => '114.114.114.114',  'country_code' => 'CN',     'location' => 'China',        'type' => 'standard'],
    ['id' => 42, 'enabled' => true,  'name' => '114DNS',          'ip' => '114.114.115.115',  'country_code' => 'CN',     'location' => 'China',        'type' => 'standard'],
    ['id' => 39, 'enabled' => true,  'name' => 'Ali DNS',         'ip' => '223.5.5.5',        'country_code' => 'CN',     'location' => 'China',        'type' => 'standard'],
    ['id' => 40, 'enabled' => true,  'name' => 'Ali DNS',         'ip' => '223.6.6.6',        'country_code' => 'CN',     'location' => 'China',        'type' => 'standard'],

    // ── Cyprus ──
    ['id' => 57, 'enabled' => false, 'name' => 'AdGuard',         'ip' => '94.140.14.14',     'country_code' => 'CY',     'location' => 'Cyprus',       'type' => 'security'],
    ['id' => 58, 'enabled' => false, 'name' => 'AdGuard',         'ip' => '94.140.15.15',     'country_code' => 'CY',     'location' => 'Cyprus',       'type' => 'security'],
    ['id' => 71, 'enabled' => false, 'name' => 'AdGuard',         'ip' => '94.140.14.15',     'country_code' => 'CY',     'location' => 'Cyprus',       'type' => 'family'],
    ['id' => 72, 'enabled' => false, 'name' => 'AdGuard',         'ip' => '94.140.15.16',     'country_code' => 'CY',     'location' => 'Cyprus',       'type' => 'family'],

    // ── Denmark ──
    ['id' => 30, 'enabled' => true,  'name' => 'UncensoredDNS',   'ip' => '91.239.100.100',   'country_code' => 'DK',     'location' => 'Denmark',      'type' => 'standard'],

    // ── Germany ──
    ['id' => 26, 'enabled' => true,  'name' => 'DNS.WATCH',       'ip' => '84.200.69.80',     'country_code' => 'DE',     'location' => 'Germany',      'type' => 'standard'],
    ['id' => 27, 'enabled' => true,  'name' => 'DNS.WATCH',       'ip' => '84.200.70.40',     'country_code' => 'DE',     'location' => 'Germany',      'type' => 'standard'],
    ['id' => 31, 'enabled' => true,  'name' => 'Hetzner',         'ip' => '185.12.64.1',      'country_code' => 'DE',     'location' => 'Germany',      'type' => 'standard'],
    ['id' => 32, 'enabled' => true,  'name' => 'Hetzner',         'ip' => '185.12.64.2',      'country_code' => 'DE',     'location' => 'Germany',      'type' => 'standard'],
    ['id' => 38, 'enabled' => true,  'name' => 'meerfarbig',      'ip' => '195.10.195.195',   'country_code' => 'DE',     'location' => 'Germany',      'type' => 'standard'],

    // ── Hong Kong ──
    ['id' => 45, 'enabled' => true,  'name' => 'HGC Global',      'ip' => '210.0.128.250',    'country_code' => 'HK',     'location' => 'Hong Kong',    'type' => 'standard'],
    ['id' => 46, 'enabled' => true,  'name' => 'HGC Global',      'ip' => '210.0.128.251',    'country_code' => 'HK',     'location' => 'Hong Kong',    'type' => 'standard'],

    // ── Japan ──
    ['id' => 50, 'enabled' => true,  'name' => 'NTT',             'ip' => '129.250.35.250',   'country_code' => 'JP',     'location' => 'Japan',        'type' => 'standard'],
    ['id' => 51, 'enabled' => true,  'name' => 'NTT',             'ip' => '129.250.35.251',   'country_code' => 'JP',     'location' => 'Japan',        'type' => 'standard'],

    // ── Luxembourg ──
    ['id' => 35, 'enabled' => true,  'name' => 'G-Core',          'ip' => '2.56.220.2',       'country_code' => 'LU',     'location' => 'Luxembourg',   'type' => 'standard'],
    ['id' => 36, 'enabled' => true,  'name' => 'G-Core',          'ip' => '95.85.95.85',      'country_code' => 'LU',     'location' => 'Luxembourg',   'type' => 'standard'],

    // ── Netherlands ──
    ['id' => 28, 'enabled' => true,  'name' => 'Freenom World',   'ip' => '80.80.80.80',      'country_code' => 'NL',     'location' => 'Netherlands',  'type' => 'standard'],
    ['id' => 29, 'enabled' => true,  'name' => 'Freenom World',   'ip' => '80.80.81.81',      'country_code' => 'NL',     'location' => 'Netherlands',  'type' => 'standard'],

    // ── Russia ──
    ['id' => 37, 'enabled' => true,  'name' => 'MSK-IX',          'ip' => '62.76.76.62',      'country_code' => 'RU',     'location' => 'Russia',       'type' => 'standard'],
    ['id' => 43, 'enabled' => true,  'name' => 'Yandex',          'ip' => '77.88.8.1',        'country_code' => 'RU',     'location' => 'Russia',       'type' => 'standard'],
    ['id' => 44, 'enabled' => true,  'name' => 'Yandex',          'ip' => '77.88.8.8',        'country_code' => 'RU',     'location' => 'Russia',       'type' => 'standard'],
    ['id' => 65, 'enabled' => false, 'name' => 'Yandex',          'ip' => '77.88.8.2',        'country_code' => 'RU',     'location' => 'Russia',       'type' => 'security'],
    ['id' => 66, 'enabled' => false, 'name' => 'Yandex',          'ip' => '77.88.8.88',       'country_code' => 'RU',     'location' => 'Russia',       'type' => 'security'],
    ['id' => 77, 'enabled' => false, 'name' => 'Yandex',          'ip' => '77.88.8.3',        'country_code' => 'RU',     'location' => 'Russia',       'type' => 'family'],
    ['id' => 78, 'enabled' => false, 'name' => 'Yandex',          'ip' => '77.88.8.7',        'country_code' => 'RU',     'location' => 'Russia',       'type' => 'family'],

    // ── South Africa ──
    ['id' => 79, 'enabled' => true,  'name' => 'Cool Ideas',      'ip' => '155.93.177.13',    'country_code' => 'ZA',     'location' => 'South Africa', 'type' => 'standard'],
    ['id' => 81, 'enabled' => true,  'name' => 'Krypton Web',     'ip' => '102.216.223.7',    'country_code' => 'ZA',     'location' => 'South Africa', 'type' => 'standard'],
    ['id' => 80, 'enabled' => true,  'name' => 'Vodacom',         'ip' => '41.23.234.129',    'country_code' => 'ZA',     'location' => 'South Africa', 'type' => 'standard'],
    ['id' => 82, 'enabled' => true,  'name' => 'X-DSL',           'ip' => '41.180.82.162',    'country_code' => 'ZA',     'location' => 'South Africa', 'type' => 'standard'],

    // ── South Korea ──
    ['id' => 49, 'enabled' => true,  'name' => 'SKB DNS',         'ip' => '210.220.163.82',   'country_code' => 'KR',     'location' => 'South Korea',  'type' => 'standard'],

    // ── Switzerland ──
    ['id' => 33, 'enabled' => true,  'name' => 'Foundation DNS',  'ip' => '37.235.1.174',     'country_code' => 'CH',     'location' => 'Switzerland',  'type' => 'standard'],
    ['id' => 34, 'enabled' => true,  'name' => 'Foundation DNS',  'ip' => '37.235.1.177',     'country_code' => 'CH',     'location' => 'Switzerland',  'type' => 'standard'],

    // ── Taiwan ──
    ['id' => 47, 'enabled' => true,  'name' => 'TWNIC',           'ip' => '101.101.101.101',  'country_code' => 'TW',     'location' => 'Taiwan',       'type' => 'standard'],
    ['id' => 48, 'enabled' => true,  'name' => 'TWNIC',           'ip' => '101.102.103.104',  'country_code' => 'TW',     'location' => 'Taiwan',       'type' => 'standard'],

    // ── UAE ──
    ['id' => 54, 'enabled' => true,  'name' => 'Comss.one',       'ip' => '92.38.152.163',    'country_code' => 'AE',     'location' => 'UAE',          'type' => 'standard'],

    // ── US ──
    ['id' => 11, 'enabled' => true,  'name' => 'Comodo Secure',   'ip' => '8.20.247.20',      'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 12, 'enabled' => true,  'name' => 'Comodo Secure',   'ip' => '8.26.56.26',       'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 23, 'enabled' => true,  'name' => 'Dyn',             'ip' => '216.146.35.35',    'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 24, 'enabled' => true,  'name' => 'Dyn',             'ip' => '216.146.36.36',    'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 25, 'enabled' => true,  'name' => 'Hurricane Elec.', 'ip' => '74.82.42.42',      'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 15, 'enabled' => true,  'name' => 'Level3',          'ip' => '4.2.2.1',          'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 16, 'enabled' => true,  'name' => 'Level3',          'ip' => '4.2.2.2',          'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 13, 'enabled' => true,  'name' => 'Neustar',         'ip' => '64.6.64.6',        'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 14, 'enabled' => true,  'name' => 'Neustar',         'ip' => '64.6.65.6',        'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 61, 'enabled' => false, 'name' => 'Neustar',         'ip' => '156.154.70.2',     'country_code' => 'US',     'location' => 'US',           'type' => 'security'],
    ['id' => 62, 'enabled' => false, 'name' => 'Neustar',         'ip' => '156.154.71.2',     'country_code' => 'US',     'location' => 'US',           'type' => 'security'],
    ['id' => 75, 'enabled' => false, 'name' => 'Neustar',         'ip' => '156.154.70.3',     'country_code' => 'US',     'location' => 'US',           'type' => 'family'],
    ['id' => 76, 'enabled' => false, 'name' => 'Neustar',         'ip' => '156.154.71.3',     'country_code' => 'US',     'location' => 'US',           'type' => 'family'],
    ['id' => 18, 'enabled' => true,  'name' => 'Norton CS',       'ip' => '199.85.126.20',    'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 19, 'enabled' => true,  'name' => 'SafeDNS',         'ip' => '195.46.39.39',     'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 20, 'enabled' => true,  'name' => 'SafeDNS',         'ip' => '195.46.39.40',     'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
    ['id' => 17, 'enabled' => true,  'name' => 'Verisign',        'ip' => '199.85.127.20',    'country_code' => 'US',     'location' => 'US',           'type' => 'standard'],
];
