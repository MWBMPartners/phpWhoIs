<?php
/**
 * DNS Propagation Resolvers
 *
 * Public DNS servers used for propagation checks. Loaded by config.php.
 * This file is auto-maintained by scripts/update-dns-resolvers.php
 *
 * Each entry:
 *   id           Unique sequential identifier
 *   enabled      true/false — set false to skip without removing
 *   name         Provider name (may repeat across entries)
 *   ip           IPv4 address
 *   country_code ISO 3166-1 alpha-2 code (used for flag display), or 'GLOBAL'
 *   location     Human-readable location label
 *   type         'standard' | 'security' (malware/threat) | 'family' (parental control)
 *   source       'manual' (hand-curated, never auto-removed) | 'public-dns' (auto-sourced)
 *   reliability  0.00–1.00 score from public-dns.info (null for manual entries)
 *
 * Sort order (enforced by scripts/update-dns-resolvers.php):
 *   1. GLOBAL entries first, then alphabetically by location
 *   2. Within each location: alphabetically by resolver name
 *   3. Within each name: by type (standard → security → family)
 *
 * Sources:
 *   https://public-dns.info/
 *   https://github.com/pingproxies/public-dns-directory
 *   https://gist.github.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5
 *   https://blog.cloudflare.com/introducing-1-1-1-1-for-families/
 *
 * Last updated: 2026-07-01 05:40:24 UTC
 */

return [
    // ── Global ──
    ['id' => 59, 'enabled' => true , 'name' => 'CleanBrowsing',       'ip' => '185.228.168.9',       'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 60, 'enabled' => false, 'name' => 'CleanBrowsing',       'ip' => '185.228.169.9',       'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 73, 'enabled' => true , 'name' => 'CleanBrowsing',       'ip' => '185.228.168.168',     'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 74, 'enabled' => false, 'name' => 'CleanBrowsing',       'ip' => '185.228.169.168',     'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' =>  3, 'enabled' => true , 'name' => 'Cloudflare',          'ip' => '1.0.0.1',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>  4, 'enabled' => true , 'name' => 'Cloudflare',          'ip' => '1.1.1.1',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 55, 'enabled' => true , 'name' => 'Cloudflare',          'ip' => '1.0.0.2',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 56, 'enabled' => false, 'name' => 'Cloudflare',          'ip' => '1.1.1.2',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 67, 'enabled' => true , 'name' => 'Cloudflare',          'ip' => '1.0.0.3',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 68, 'enabled' => false, 'name' => 'Cloudflare',          'ip' => '1.1.1.3',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' =>  9, 'enabled' => true , 'name' => 'DNS.SB',              'ip' => '185.222.222.222',     'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 10, 'enabled' => true , 'name' => 'DNS.SB',              'ip' => '45.11.45.11',         'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>  1, 'enabled' => true , 'name' => 'Google',              'ip' => '8.8.4.4',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>  2, 'enabled' => true , 'name' => 'Google',              'ip' => '8.8.8.8',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>  7, 'enabled' => true , 'name' => 'OpenDNS',             'ip' => '208.67.220.220',      'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>  8, 'enabled' => true , 'name' => 'OpenDNS',             'ip' => '208.67.222.222',      'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 69, 'enabled' => true , 'name' => 'OpenDNS',             'ip' => '208.67.220.123',      'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 70, 'enabled' => false, 'name' => 'OpenDNS',             'ip' => '208.67.222.123',      'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' =>  5, 'enabled' => true , 'name' => 'Quad9',               'ip' => '149.112.112.112',     'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>  6, 'enabled' => true , 'name' => 'Quad9',               'ip' => '9.9.9.9',             'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 63, 'enabled' => true , 'name' => 'Quad9',               'ip' => '149.112.112.11',      'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 64, 'enabled' => false, 'name' => 'Quad9',               'ip' => '9.9.9.11',            'country_code' => 'GLOBAL',  'location' => 'Global',          'type' => 'security',    'source' => 'manual',      'reliability' => null],

    // ── Argentina ──
    ['id' =>124, 'enabled' => true , 'name' => 'customer-static-210-8-69.iplannetworks.net.', 'ip' => '190.210.8.69',        'country_code' => 'AR',      'location' => 'Argentina',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>123, 'enabled' => true , 'name' => 'host187.advance.com.ar.', 'ip' => '200.16.208.187',      'country_code' => 'AR',      'location' => 'Argentina',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Australia ──
    ['id' =>128, 'enabled' => true , 'name' => 'sydney.cdn.parrot.sh.', 'ip' => '172.105.162.206',     'country_code' => 'AU',      'location' => 'Australia',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>127, 'enabled' => true , 'name' => 'Telstra Corporation Ltd', 'ip' => '139.134.5.51',        'country_code' => 'AU',      'location' => 'Australia',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Austria ──
    ['id' =>185, 'enabled' => true , 'name' => '194-208-013-007.tele.net.', 'ip' => '194.208.13.7',        'country_code' => 'AT',      'location' => 'Austria',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>186, 'enabled' => true , 'name' => 'lemb.one.',           'ip' => '202.61.196.175',      'country_code' => 'AT',      'location' => 'Austria',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Bangladesh ──
    ['id' =>117, 'enabled' => true , 'name' => 'pubdns1.kloud.net.bd.', 'ip' => '103.146.221.20',      'country_code' => 'BD',      'location' => 'Bangladesh',      'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>118, 'enabled' => true , 'name' => 'pubdns2.kloud.net.bd.', 'ip' => '103.146.221.21',      'country_code' => 'BD',      'location' => 'Bangladesh',      'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Belgium ──
    ['id' =>101, 'enabled' => true , 'name' => 'cache0100.ns.eu.uu.net.', 'ip' => '194.7.1.4',           'country_code' => 'BE',      'location' => 'Belgium',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>102, 'enabled' => true , 'name' => 'ip-83-134-123-101.dsl.scarlet.be.', 'ip' => '83.134.123.101',      'country_code' => 'BE',      'location' => 'Belgium',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Brazil ──
    ['id' =>109, 'enabled' => true , 'name' => '177-184-176-5.netcartelecom.com.br.', 'ip' => '177.184.176.5',       'country_code' => 'BR',      'location' => 'Brazil',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 53, 'enabled' => true , 'name' => 'Censurfridns',        'ip' => '89.233.43.71',        'country_code' => 'BR',      'location' => 'Brazil',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>110, 'enabled' => true , 'name' => 'FamaNet Tecnologia e Informatica LTDA', 'ip' => '179.109.15.42',       'country_code' => 'BR',      'location' => 'Brazil',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Bulgaria ──
    ['id' => 83, 'enabled' => true , 'name' => 'hst-26-2.medicom.bg.', 'ip' => '82.146.26.2',         'country_code' => 'BG',      'location' => 'Bulgaria',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 84, 'enabled' => true , 'name' => 'Skynet Ltd',          'ip' => '46.35.180.2',         'country_code' => 'BG',      'location' => 'Bulgaria',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Canada ──
    ['id' => 21, 'enabled' => true , 'name' => 'CIRA Shield',         'ip' => '149.112.121.10',      'country_code' => 'CA',      'location' => 'Canada',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 22, 'enabled' => true , 'name' => 'CIRA Shield',         'ip' => '149.112.122.10',      'country_code' => 'CA',      'location' => 'Canada',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 92, 'enabled' => true , 'name' => 'dns1.van.radiant.net.', 'ip' => '216.21.128.22',       'country_code' => 'CA',      'location' => 'Canada',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 91, 'enabled' => true , 'name' => 'unallocated-static.rogers.com.', 'ip' => '66.209.53.88',        'country_code' => 'CA',      'location' => 'Canada',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Chile ──
    ['id' =>125, 'enabled' => true , 'name' => 'Gtd Internet S.A.',   'ip' => '190.96.61.146',       'country_code' => 'CL',      'location' => 'Chile',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>126, 'enabled' => true , 'name' => 'ZAM LTDA.',           'ip' => '186.64.123.114',      'country_code' => 'CL',      'location' => 'Chile',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── China ──
    ['id' => 41, 'enabled' => true , 'name' => '114DNS',              'ip' => '114.114.114.114',     'country_code' => 'CN',      'location' => 'China',           'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 42, 'enabled' => true , 'name' => '114DNS',              'ip' => '114.114.115.115',     'country_code' => 'CN',      'location' => 'China',           'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 39, 'enabled' => true , 'name' => 'Ali DNS',             'ip' => '223.5.5.5',           'country_code' => 'CN',      'location' => 'China',           'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 40, 'enabled' => true , 'name' => 'Ali DNS',             'ip' => '223.6.6.6',           'country_code' => 'CN',      'location' => 'China',           'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Colombia ──
    ['id' =>161, 'enabled' => true , 'name' => 'azteca-comunicaciones.com.', 'ip' => '177.93.44.64',        'country_code' => 'CO',      'location' => 'Colombia',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>162, 'enabled' => true , 'name' => 'cable190-248-153-162.une.net.co.', 'ip' => '190.248.153.162',     'country_code' => 'CO',      'location' => 'Colombia',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Croatia ──
    ['id' =>174, 'enabled' => true , 'name' => 'cl49.db-informatika.hr.', 'ip' => '185.46.34.49',        'country_code' => 'HR',      'location' => 'Croatia',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>173, 'enabled' => true , 'name' => 'srv-212-15-169-50.static.a1.hr.', 'ip' => '212.15.169.50',       'country_code' => 'HR',      'location' => 'Croatia',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Cyprus ──
    ['id' =>107, 'enabled' => true , 'name' => '176-103-130-136.dns.adguard.com.', 'ip' => '176.103.130.136',     'country_code' => 'CY',      'location' => 'Cyprus',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>108, 'enabled' => true , 'name' => '176-103-130-137.dns.adguard.com.', 'ip' => '176.103.130.137',     'country_code' => 'CY',      'location' => 'Cyprus',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 57, 'enabled' => true , 'name' => 'AdGuard',             'ip' => '94.140.14.14',        'country_code' => 'CY',      'location' => 'Cyprus',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 58, 'enabled' => false, 'name' => 'AdGuard',             'ip' => '94.140.15.15',        'country_code' => 'CY',      'location' => 'Cyprus',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 71, 'enabled' => true , 'name' => 'AdGuard',             'ip' => '94.140.14.15',        'country_code' => 'CY',      'location' => 'Cyprus',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 72, 'enabled' => false, 'name' => 'AdGuard',             'ip' => '94.140.15.16',        'country_code' => 'CY',      'location' => 'Cyprus',          'type' => 'family',      'source' => 'manual',      'reliability' => null],

    // ── Czech Republic ──
    ['id' =>156, 'enabled' => true , 'name' => 'homer.thcnet.cz.',    'ip' => '213.211.50.2',        'country_code' => 'CZ',      'location' => 'Czech Republic',  'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>155, 'enabled' => true , 'name' => 'ns.cesnet.cz.',       'ip' => '195.113.144.194',     'country_code' => 'CZ',      'location' => 'Czech Republic',  'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Denmark ──
    ['id' =>149, 'enabled' => true , 'name' => 'deic-ore.anycast.censurfridns.dk.', 'ip' => '130.226.161.34',      'country_code' => 'DK',      'location' => 'Denmark',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>150, 'enabled' => true , 'name' => 'Kracon ApS',          'ip' => '185.38.27.139',       'country_code' => 'DK',      'location' => 'Denmark',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 30, 'enabled' => true , 'name' => 'UncensoredDNS',       'ip' => '91.239.100.100',      'country_code' => 'DK',      'location' => 'Denmark',         'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Egypt ──
    ['id' =>181, 'enabled' => true , 'name' => 'Etisalat Misr',       'ip' => '154.236.189.28',      'country_code' => 'EG',      'location' => 'Egypt',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>182, 'enabled' => true , 'name' => 'mans.edu.eg.',        'ip' => '193.227.50.3',        'country_code' => 'EG',      'location' => 'Egypt',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Estonia ──
    ['id' =>152, 'enabled' => true , 'name' => '95145.fill.ee.',      'ip' => '91.146.95.145',       'country_code' => 'EE',      'location' => 'Estonia',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>151, 'enabled' => true , 'name' => 's97d01d5f.fastvps-server.com.', 'ip' => '46.36.219.173',       'country_code' => 'EE',      'location' => 'Estonia',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Finland ──
    ['id' =>119, 'enabled' => true , 'name' => 'resolver1.dns.trex.fi.', 'ip' => '195.140.195.21',      'country_code' => 'FI',      'location' => 'Finland',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>120, 'enabled' => true , 'name' => 'static.121.151.21.65.clients.your-server.de.', 'ip' => '65.21.151.121',       'country_code' => 'FI',      'location' => 'Finland',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── France ──
    ['id' => 88, 'enabled' => true , 'name' => 'ip-234.net-89-2-2.static.numericable.fr.', 'ip' => '89.2.2.234',          'country_code' => 'FR',      'location' => 'France',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 87, 'enabled' => true , 'name' => 'ip115.ip-51-254-25.eu.', 'ip' => '51.254.25.115',       'country_code' => 'FR',      'location' => 'France',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Germany ──
    ['id' => 26, 'enabled' => true , 'name' => 'DNS.WATCH',           'ip' => '84.200.69.80',        'country_code' => 'DE',      'location' => 'Germany',         'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 27, 'enabled' => true , 'name' => 'DNS.WATCH',           'ip' => '84.200.70.40',        'country_code' => 'DE',      'location' => 'Germany',         'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 31, 'enabled' => true , 'name' => 'Hetzner',             'ip' => '185.12.64.1',         'country_code' => 'DE',      'location' => 'Germany',         'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 32, 'enabled' => true , 'name' => 'Hetzner',             'ip' => '185.12.64.2',         'country_code' => 'DE',      'location' => 'Germany',         'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 38, 'enabled' => true , 'name' => 'meerfarbig',          'ip' => '195.10.195.195',      'country_code' => 'DE',      'location' => 'Germany',         'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Greece ──
    ['id' =>113, 'enabled' => true , 'name' => 'opennict2.libreops.cc.', 'ip' => '192.71.166.92',       'country_code' => 'GR',      'location' => 'Greece',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>114, 'enabled' => true , 'name' => 'ppp-2-85-104-249.home.otenet.gr.', 'ip' => '2.85.104.249',        'country_code' => 'GR',      'location' => 'Greece',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Hong Kong ──
    ['id' =>106, 'enabled' => true , 'name' => '123203156079.ctinets.com.', 'ip' => '123.203.156.79',      'country_code' => 'HK',      'location' => 'Hong Kong',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>105, 'enabled' => true , 'name' => '197.68.198.203.static.netvigator.com.', 'ip' => '203.198.68.197',      'country_code' => 'HK',      'location' => 'Hong Kong',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 45, 'enabled' => true , 'name' => 'HGC Global',          'ip' => '210.0.128.250',       'country_code' => 'HK',      'location' => 'Hong Kong',       'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 46, 'enabled' => true , 'name' => 'HGC Global',          'ip' => '210.0.128.251',       'country_code' => 'HK',      'location' => 'Hong Kong',       'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Hungary ──
    ['id' =>116, 'enabled' => true , 'name' => 'Budapesti Corvinus Egyetem', 'ip' => '146.110.42.26',       'country_code' => 'HU',      'location' => 'Hungary',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>115, 'enabled' => true , 'name' => 'mail.andapresent.hu.', 'ip' => '79.120.177.106',      'country_code' => 'HU',      'location' => 'Hungary',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── India ──
    ['id' =>121, 'enabled' => true , 'name' => 'ns9.maharashtra.gov.in.', 'ip' => '103.23.150.89',       'country_code' => 'IN',      'location' => 'India',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>122, 'enabled' => true , 'name' => 'Reliance Communications Ltd.DAKC MUMBAI', 'ip' => '202.138.120.87',      'country_code' => 'IN',      'location' => 'India',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Indonesia ──
    ['id' => 86, 'enabled' => true , 'name' => '114-6-227-28.resources.indosat.com.', 'ip' => '114.6.227.28',        'country_code' => 'ID',      'location' => 'Indonesia',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 85, 'enabled' => true , 'name' => 'PT Telemedia Network Cakrawala', 'ip' => '103.15.242.145',      'country_code' => 'ID',      'location' => 'Indonesia',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Iran ──
    ['id' =>146, 'enabled' => true , 'name' => 'Dadeh Gostar Asr Novin P.J.S. Co.', 'ip' => '46.224.1.42',         'country_code' => 'IR',      'location' => 'Iran',            'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>145, 'enabled' => true , 'name' => 'Noyan Abr Arvan Co. ( Private Joint Stock)', 'ip' => '185.231.182.126',     'country_code' => 'IR',      'location' => 'Iran',            'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Ireland ──
    ['id' =>194, 'enabled' => true , 'name' => 'ec2-3-249-115-37.eu-west-1.compute.amazonaws.com.', 'ip' => '3.249.115.37',        'country_code' => 'IE',      'location' => 'Ireland',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>193, 'enabled' => true , 'name' => 'MICROSOFT-CORP-MSN-AS-BLOCK', 'ip' => '23.102.21.142',       'country_code' => 'IE',      'location' => 'Ireland',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Israel ──
    ['id' =>158, 'enabled' => true , 'name' => '80.179.226.56.cable.012.net.il.', 'ip' => '80.179.226.56',       'country_code' => 'IL',      'location' => 'Israel',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>157, 'enabled' => true , 'name' => 'Partner Communications Ltd.', 'ip' => '213.8.5.220',         'country_code' => 'IL',      'location' => 'Israel',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Italy ──
    ['id' => 96, 'enabled' => true , 'name' => '83-103-61-107.ip.fastwebnet.it.', 'ip' => '83.103.61.107',       'country_code' => 'IT',      'location' => 'Italy',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 95, 'enabled' => true , 'name' => 'dns.aruba.it.',       'ip' => '62.149.128.4',        'country_code' => 'IT',      'location' => 'Italy',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Japan ──
    ['id' =>163, 'enabled' => true , 'name' => 'dns.nifty.com.',      'ip' => '202.248.37.74',       'country_code' => 'JP',      'location' => 'Japan',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 50, 'enabled' => true , 'name' => 'NTT',                 'ip' => '129.250.35.250',      'country_code' => 'JP',      'location' => 'Japan',           'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 51, 'enabled' => true , 'name' => 'NTT',                 'ip' => '129.250.35.251',      'country_code' => 'JP',      'location' => 'Japan',           'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>164, 'enabled' => true , 'name' => 'NTT PC Communications, Inc.', 'ip' => '1.33.184.194',        'country_code' => 'JP',      'location' => 'Japan',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Kenya ──
    ['id' =>197, 'enabled' => true , 'name' => 'JTL',                 'ip' => '197.232.253.210',     'country_code' => 'KE',      'location' => 'Kenya',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>198, 'enabled' => true , 'name' => 'JTL',                 'ip' => '197.232.47.102',      'country_code' => 'KE',      'location' => 'Kenya',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Latvia ──
    ['id' =>189, 'enabled' => true , 'name' => 'SIA Datu Tehnologiju Grupa', 'ip' => '91.135.20.86',        'country_code' => 'LV',      'location' => 'Latvia',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>190, 'enabled' => true , 'name' => 'SIA Serverum',        'ip' => '212.6.44.218',        'country_code' => 'LV',      'location' => 'Latvia',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Lithuania ──
    ['id' =>147, 'enabled' => true , 'name' => '82-135-139-155.static.zebra.lt.', 'ip' => '82.135.139.155',      'country_code' => 'LT',      'location' => 'Lithuania',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>148, 'enabled' => true , 'name' => 'Telia Lietuva, AB',   'ip' => '85.206.107.169',      'country_code' => 'LT',      'location' => 'Lithuania',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Luxembourg ──
    ['id' => 35, 'enabled' => true , 'name' => 'G-Core',              'ip' => '2.56.220.2',          'country_code' => 'LU',      'location' => 'Luxembourg',      'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 36, 'enabled' => true , 'name' => 'G-Core',              'ip' => '95.85.95.85',         'country_code' => 'LU',      'location' => 'Luxembourg',      'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>196, 'enabled' => true , 'name' => 'PONYNET',             'ip' => '107.189.28.80',       'country_code' => 'LU',      'location' => 'Luxembourg',      'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>195, 'enabled' => true , 'name' => 'vodsl-11059.vo.lu.',  'ip' => '85.93.209.51',        'country_code' => 'LU',      'location' => 'Luxembourg',      'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Malaysia ──
    ['id' =>168, 'enabled' => true , 'name' => 'TIME dotCom Berhad No. 14, Jalan Majistret U126 Hicom Glenmarie Industrial Park 40150 Shah Al', 'ip' => '211.25.11.15',        'country_code' => 'MY',      'location' => 'Malaysia',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>167, 'enabled' => true , 'name' => 'TM Net, Internet Service Provider', 'ip' => '1.32.122.32',         'country_code' => 'MY',      'location' => 'Malaysia',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Mexico ──
    ['id' =>140, 'enabled' => true , 'name' => 'dns-cache-mty1.alestra.net.mx.', 'ip' => '207.248.224.71',      'country_code' => 'MX',      'location' => 'Mexico',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>139, 'enabled' => true , 'name' => 'env2.b-enlinea.mx.',  'ip' => '207.248.224.72',      'country_code' => 'MX',      'location' => 'Mexico',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Netherlands ──
    ['id' => 89, 'enabled' => true , 'name' => 'cache0206.ns.eu.uu.net.', 'ip' => '195.129.12.83',       'country_code' => 'NL',      'location' => 'Netherlands',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 28, 'enabled' => true , 'name' => 'Freenom World',       'ip' => '80.80.80.80',         'country_code' => 'NL',      'location' => 'Netherlands',     'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 29, 'enabled' => true , 'name' => 'Freenom World',       'ip' => '80.80.81.81',         'country_code' => 'NL',      'location' => 'Netherlands',     'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 90, 'enabled' => true , 'name' => 'nl.ahadns.net.',      'ip' => '5.2.75.75',           'country_code' => 'NL',      'location' => 'Netherlands',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── New Zealand ──
    ['id' =>188, 'enabled' => true , 'name' => '125-239-155-163-fibre.sparkbb.co.nz.', 'ip' => '125.239.155.163',     'country_code' => 'NZ',      'location' => 'New Zealand',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>187, 'enabled' => true , 'name' => 'MYREPUBLIC LIMITED',  'ip' => '158.140.238.43',      'country_code' => 'NZ',      'location' => 'New Zealand',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Nigeria ──
    ['id' =>165, 'enabled' => true , 'name' => 'MTN NIGERIA Communication limited', 'ip' => '83.143.8.249',        'country_code' => 'NG',      'location' => 'Nigeria',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>166, 'enabled' => true , 'name' => 'proxy_server.hooptelecoms.com.', 'ip' => '169.239.48.11',       'country_code' => 'NG',      'location' => 'Nigeria',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Norway ──
    ['id' => 98, 'enabled' => true , 'name' => 'iris088.irisinfo.net.', 'ip' => '89.191.14.88',        'country_code' => 'NO',      'location' => 'Norway',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 97, 'enabled' => true , 'name' => 'munch.absnet.no.',    'ip' => '217.170.128.27',      'country_code' => 'NO',      'location' => 'Norway',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Pakistan ──
    ['id' =>171, 'enabled' => true , 'name' => '125-209-66-170.multi.net.pk.', 'ip' => '125.209.66.170',      'country_code' => 'PK',      'location' => 'Pakistan',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>172, 'enabled' => true , 'name' => 'Pakistan Telecommunication Company Limited', 'ip' => '59.103.243.83',       'country_code' => 'PK',      'location' => 'Pakistan',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Peru ──
    ['id' =>177, 'enabled' => true , 'name' => 'OPTICAL TECHNOLOGIES S.A.C.', 'ip' => '190.12.95.170',       'country_code' => 'PE',      'location' => 'Peru',            'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>178, 'enabled' => true , 'name' => 'Telefonica del Peru S.A.A.', 'ip' => '200.60.60.58',        'country_code' => 'PE',      'location' => 'Peru',            'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Philippines ──
    ['id' =>160, 'enabled' => true , 'name' => 'Globe Telecoms',      'ip' => '120.28.57.114',       'country_code' => 'PH',      'location' => 'Philippines',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>159, 'enabled' => true , 'name' => 'nsvip.skyinet.net.',  'ip' => '202.78.97.41',        'country_code' => 'PH',      'location' => 'Philippines',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Poland ──
    ['id' =>138, 'enabled' => true , 'name' => '78-11-44-46.static.ip.netia.com.pl.', 'ip' => '78.11.44.46',         'country_code' => 'PL',      'location' => 'Poland',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>137, 'enabled' => true , 'name' => 'prsrv1.man.radom.pl.', 'ip' => '193.111.144.145',     'country_code' => 'PL',      'location' => 'Poland',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Portugal ──
    ['id' =>111, 'enabled' => true , 'name' => 'Fundacao para a Ciencia e a Tecnologia, I.P.', 'ip' => '193.137.7.225',       'country_code' => 'PT',      'location' => 'Portugal',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>112, 'enabled' => true , 'name' => 'mgarces2.evolute.pt.', 'ip' => '5.206.228.37',        'country_code' => 'PT',      'location' => 'Portugal',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Romania ──
    ['id' => 94, 'enabled' => true , 'name' => 'nsx.euroweb.ro.',     'ip' => '193.230.183.201',     'country_code' => 'RO',      'location' => 'Romania',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 93, 'enabled' => true , 'name' => 'tag.euroweb.ro.',     'ip' => '193.226.61.1',        'country_code' => 'RO',      'location' => 'Romania',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Russia ──
    ['id' => 37, 'enabled' => true , 'name' => 'MSK-IX',              'ip' => '62.76.76.62',         'country_code' => 'RU',      'location' => 'Russia',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 43, 'enabled' => true , 'name' => 'Yandex',              'ip' => '77.88.8.1',           'country_code' => 'RU',      'location' => 'Russia',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 44, 'enabled' => true , 'name' => 'Yandex',              'ip' => '77.88.8.8',           'country_code' => 'RU',      'location' => 'Russia',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 65, 'enabled' => true , 'name' => 'Yandex',              'ip' => '77.88.8.2',           'country_code' => 'RU',      'location' => 'Russia',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 66, 'enabled' => false, 'name' => 'Yandex',              'ip' => '77.88.8.88',          'country_code' => 'RU',      'location' => 'Russia',          'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 77, 'enabled' => true , 'name' => 'Yandex',              'ip' => '77.88.8.3',           'country_code' => 'RU',      'location' => 'Russia',          'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 78, 'enabled' => false, 'name' => 'Yandex',              'ip' => '77.88.8.7',           'country_code' => 'RU',      'location' => 'Russia',          'type' => 'family',      'source' => 'manual',      'reliability' => null],

    // ── Saudi Arabia ──
    ['id' =>200, 'enabled' => true , 'name' => 'Saudi Telecom Company JSC', 'ip' => '2.88.148.46',         'country_code' => 'SA',      'location' => 'Saudi Arabia',    'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>199, 'enabled' => true , 'name' => 'Saudi Telecom Company JSC', 'ip' => '2.88.93.191',         'country_code' => 'SA',      'location' => 'Saudi Arabia',    'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Serbia ──
    ['id' =>176, 'enabled' => true , 'name' => 'TELEKOM SRBIJA a.d.', 'ip' => '77.46.138.33',        'country_code' => 'RS',      'location' => 'Serbia',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>175, 'enabled' => true , 'name' => 'TELEKOM SRBIJA a.d.', 'ip' => '79.101.99.2',         'country_code' => 'RS',      'location' => 'Serbia',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Singapore ──
    ['id' =>154, 'enabled' => true , 'name' => 'dns02.ntts-idc.net.sg.', 'ip' => '202.136.163.11',      'country_code' => 'SG',      'location' => 'Singapore',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>153, 'enabled' => true , 'name' => 'dns03.ntts-idc.net.sg.', 'ip' => '202.136.162.12',      'country_code' => 'SG',      'location' => 'Singapore',       'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Slovakia ──
    ['id' =>179, 'enabled' => true , 'name' => 'stip-static-225.213-81-218.telecom.sk.', 'ip' => '213.81.218.225',      'country_code' => 'SK',      'location' => 'Slovakia',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>180, 'enabled' => true , 'name' => 'SWAN, a.s.',          'ip' => '195.168.91.238',      'country_code' => 'SK',      'location' => 'Slovakia',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── South Africa ──
    ['id' => 79, 'enabled' => true , 'name' => 'Cool Ideas',          'ip' => '155.93.177.13',       'country_code' => 'ZA',      'location' => 'South Africa',    'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 81, 'enabled' => true , 'name' => 'Krypton Web',         'ip' => '102.216.223.7',       'country_code' => 'ZA',      'location' => 'South Africa',    'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 80, 'enabled' => true , 'name' => 'Vodacom',             'ip' => '41.23.234.129',       'country_code' => 'ZA',      'location' => 'South Africa',    'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 82, 'enabled' => true , 'name' => 'X-DSL',               'ip' => '41.180.82.162',       'country_code' => 'ZA',      'location' => 'South Africa',    'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── South Korea ──
    ['id' =>131, 'enabled' => true , 'name' => 'INHA UNIVERSITY',     'ip' => '165.246.10.2',        'country_code' => 'KR',      'location' => 'South Korea',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>132, 'enabled' => true , 'name' => 'Korea Telecom',       'ip' => '218.146.255.235',     'country_code' => 'KR',      'location' => 'South Korea',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 49, 'enabled' => true , 'name' => 'SKB DNS',             'ip' => '210.220.163.82',      'country_code' => 'KR',      'location' => 'South Korea',     'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Spain ──
    ['id' =>104, 'enabled' => true , 'name' => '10.red-195-77-235.customer.static.ccgg.telefonica.net.', 'ip' => '195.77.235.10',       'country_code' => 'ES',      'location' => 'Spain',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>103, 'enabled' => true , 'name' => 'damia.altanet.org.',  'ip' => '195.76.233.2',        'country_code' => 'ES',      'location' => 'Spain',           'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Sweden ──
    ['id' =>192, 'enabled' => true , 'name' => 'ec2-13-51-179-100.eu-north-1.compute.amazonaws.com.', 'ip' => '13.51.179.100',       'country_code' => 'SE',      'location' => 'Sweden',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>191, 'enabled' => true , 'name' => 'loopia-vps-0867c86f-da63-482e-b924-c844994d1725-1842.loopiavps.com.', 'ip' => '213.188.153.178',     'country_code' => 'SE',      'location' => 'Sweden',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Switzerland ──
    ['id' => 33, 'enabled' => true , 'name' => 'Foundation DNS',      'ip' => '37.235.1.174',        'country_code' => 'CH',      'location' => 'Switzerland',     'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 34, 'enabled' => true , 'name' => 'Foundation DNS',      'ip' => '37.235.1.177',        'country_code' => 'CH',      'location' => 'Switzerland',     'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>133, 'enabled' => true , 'name' => 'oltdzpsp-cns005.bluewin.ch.', 'ip' => '195.186.1.107',       'country_code' => 'CH',      'location' => 'Switzerland',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>134, 'enabled' => true , 'name' => 'zhhdzpsp-cns002.bluewin.ch.', 'ip' => '195.186.4.109',       'country_code' => 'CH',      'location' => 'Switzerland',     'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Taiwan ──
    ['id' =>130, 'enabled' => true , 'name' => '60-248-107-138.hinet-ip.hinet.net.', 'ip' => '60.248.107.138',      'country_code' => 'TW',      'location' => 'Taiwan',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>129, 'enabled' => true , 'name' => 'dns.hinet.net.',      'ip' => '168.95.1.1',          'country_code' => 'TW',      'location' => 'Taiwan',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' => 47, 'enabled' => true , 'name' => 'TWNIC',               'ip' => '101.101.101.101',     'country_code' => 'TW',      'location' => 'Taiwan',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 48, 'enabled' => true , 'name' => 'TWNIC',               'ip' => '101.102.103.104',     'country_code' => 'TW',      'location' => 'Taiwan',          'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Thailand ──
    ['id' =>142, 'enabled' => true , 'name' => 'mail.successmore4.COM.', 'ip' => '203.146.127.85',      'country_code' => 'TH',      'location' => 'Thailand',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>141, 'enabled' => true , 'name' => 'ns01.csloxinfo.com.', 'ip' => '203.146.237.237',     'country_code' => 'TH',      'location' => 'Thailand',        'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Turkey ──
    ['id' =>169, 'enabled' => true , 'name' => '95.9.194.13.static.ttnet.com.tr.', 'ip' => '95.9.194.13',         'country_code' => 'TR',      'location' => 'Turkey',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>170, 'enabled' => true , 'name' => 'host-92-45-59-195.reverse.superonline.net.', 'ip' => '92.45.59.195',        'country_code' => 'TR',      'location' => 'Turkey',          'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── UAE ──
    ['id' => 54, 'enabled' => true , 'name' => 'Comss.one',           'ip' => '92.38.152.163',       'country_code' => 'AE',      'location' => 'UAE',             'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' =>184, 'enabled' => true , 'name' => 'Emirates Integrated Telecommunications Company PJSC', 'ip' => '87.200.60.14',        'country_code' => 'AE',      'location' => 'UAE',             'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>183, 'enabled' => true , 'name' => 'ORACLE-BMC-31898',    'ip' => '193.123.68.154',      'country_code' => 'AE',      'location' => 'UAE',             'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── UK ──
    ['id' => 99, 'enabled' => true , 'name' => 'cache0000.ns.eu.uu.net.', 'ip' => '158.43.128.72',       'country_code' => 'GB',      'location' => 'UK',              'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>100, 'enabled' => true , 'name' => 'cache0005a.ns.eu.uu.net.', 'ip' => '158.43.240.3',        'country_code' => 'GB',      'location' => 'UK',              'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── Ukraine ──
    ['id' =>136, 'enabled' => true , 'name' => 'ip102-156-200-109.crelcom.ru.', 'ip' => '109.200.156.102',     'country_code' => 'UA',      'location' => 'Ukraine',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>135, 'enabled' => true , 'name' => 'PE Ivanov Vitaliy Sergeevich', 'ip' => '147.78.3.252',        'country_code' => 'UA',      'location' => 'Ukraine',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],

    // ── US ──
    ['id' => 11, 'enabled' => true , 'name' => 'Comodo Secure',       'ip' => '8.20.247.20',         'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 12, 'enabled' => true , 'name' => 'Comodo Secure',       'ip' => '8.26.56.26',          'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 23, 'enabled' => true , 'name' => 'Dyn',                 'ip' => '216.146.35.35',       'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 24, 'enabled' => true , 'name' => 'Dyn',                 'ip' => '216.146.36.36',       'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 25, 'enabled' => true , 'name' => 'Hurricane Elec.',     'ip' => '74.82.42.42',         'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 15, 'enabled' => true , 'name' => 'Level3',              'ip' => '4.2.2.1',             'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 16, 'enabled' => true , 'name' => 'Level3',              'ip' => '4.2.2.2',             'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 13, 'enabled' => true , 'name' => 'Neustar',             'ip' => '64.6.64.6',           'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 14, 'enabled' => true , 'name' => 'Neustar',             'ip' => '64.6.65.6',           'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 61, 'enabled' => true , 'name' => 'Neustar',             'ip' => '156.154.70.2',        'country_code' => 'US',      'location' => 'US',              'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 62, 'enabled' => false, 'name' => 'Neustar',             'ip' => '156.154.71.2',        'country_code' => 'US',      'location' => 'US',              'type' => 'security',    'source' => 'manual',      'reliability' => null],
    ['id' => 75, 'enabled' => true , 'name' => 'Neustar',             'ip' => '156.154.70.3',        'country_code' => 'US',      'location' => 'US',              'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 76, 'enabled' => false, 'name' => 'Neustar',             'ip' => '156.154.71.3',        'country_code' => 'US',      'location' => 'US',              'type' => 'family',      'source' => 'manual',      'reliability' => null],
    ['id' => 18, 'enabled' => true , 'name' => 'Norton CS',           'ip' => '199.85.126.20',       'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 19, 'enabled' => true , 'name' => 'SafeDNS',             'ip' => '195.46.39.39',        'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 20, 'enabled' => true , 'name' => 'SafeDNS',             'ip' => '195.46.39.40',        'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],
    ['id' => 17, 'enabled' => true , 'name' => 'Verisign',            'ip' => '199.85.127.20',       'country_code' => 'US',      'location' => 'US',              'type' => 'standard',    'source' => 'manual',      'reliability' => null],

    // ── Vietnam ──
    ['id' =>143, 'enabled' => true , 'name' => 'nscache2.vnnic.net.vn.', 'ip' => '203.119.36.106',      'country_code' => 'VN',      'location' => 'Vietnam',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
    ['id' =>144, 'enabled' => true , 'name' => 'static.vnpt.vn.',     'ip' => '113.191.251.66',      'country_code' => 'VN',      'location' => 'Vietnam',         'type' => 'standard',    'source' => 'public-dns',  'reliability' => 1.00],
];
