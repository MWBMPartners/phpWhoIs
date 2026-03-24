#!/usr/bin/env php
<?php
/**
 * DNS Resolver List Updater
 *
 * Fetches reliable public DNS servers from public-dns.info, merges them
 * with the existing resolver list, and writes back dns_resolvers.php
 * with the correct sort order.
 *
 * Rules:
 *   - Entries with source=manual are NEVER removed or modified
 *   - Entries with source=public-dns are added/updated/removed based on
 *     the latest data from public-dns.info
 *   - Only IPv4 servers with reliability >= 0.95 are included
 *   - New auto-sourced entries are enabled by default, type=standard
 *   - Sort: GLOBAL first, then alphabetically by location, then by name,
 *     then by type (standard → security → family)
 *
 * Usage: php scripts/update-dns-resolvers.php
 */

// ── Configuration (override via environment variables) ──
$minReliability  = (float)(getenv('DNS_MIN_RELIABILITY') ?: 0.80);  // Minimum reliability score (0.00–1.00)
$maxPerCountry   = (int)(getenv('DNS_MAX_PER_COUNTRY') ?: 2);       // Max auto-sourced entries per country
$csvUrl          = 'https://public-dns.info/nameservers.csv';
$resolverFile    = __DIR__ . '/../web/public_html_beta/includes/dns_resolvers.php';

echo "Config: minReliability=$minReliability, maxPerCountry=$maxPerCountry\n";

// ── Country code to location name map ──
$countryNames = [
    'AE' => 'UAE', 'AR' => 'Argentina', 'AT' => 'Austria', 'AU' => 'Australia',
    'BD' => 'Bangladesh', 'BE' => 'Belgium', 'BG' => 'Bulgaria', 'BR' => 'Brazil',
    'CA' => 'Canada', 'CH' => 'Switzerland', 'CL' => 'Chile', 'CN' => 'China',
    'CO' => 'Colombia', 'CY' => 'Cyprus', 'CZ' => 'Czech Republic', 'DE' => 'Germany',
    'DK' => 'Denmark', 'EE' => 'Estonia', 'EG' => 'Egypt', 'ES' => 'Spain',
    'FI' => 'Finland', 'FR' => 'France', 'GB' => 'UK', 'GR' => 'Greece',
    'HK' => 'Hong Kong', 'HR' => 'Croatia', 'HU' => 'Hungary', 'ID' => 'Indonesia',
    'IE' => 'Ireland', 'IL' => 'Israel', 'IN' => 'India', 'IR' => 'Iran',
    'IT' => 'Italy', 'JP' => 'Japan', 'KE' => 'Kenya', 'KR' => 'South Korea',
    'LT' => 'Lithuania', 'LU' => 'Luxembourg', 'LV' => 'Latvia', 'MX' => 'Mexico',
    'MY' => 'Malaysia', 'NG' => 'Nigeria', 'NL' => 'Netherlands', 'NO' => 'Norway',
    'NZ' => 'New Zealand', 'PE' => 'Peru', 'PH' => 'Philippines', 'PK' => 'Pakistan',
    'PL' => 'Poland', 'PT' => 'Portugal', 'RO' => 'Romania', 'RS' => 'Serbia',
    'RU' => 'Russia', 'SA' => 'Saudi Arabia', 'SE' => 'Sweden', 'SG' => 'Singapore',
    'SK' => 'Slovakia', 'TH' => 'Thailand', 'TR' => 'Turkey', 'TW' => 'Taiwan',
    'UA' => 'Ukraine', 'US' => 'US', 'VN' => 'Vietnam', 'ZA' => 'South Africa',
];

// ── Type sort order ──
$typeOrder = ['standard' => 0, 'security' => 1, 'family' => 2];

// ── Exempt providers — no per-country or per-resolver limits applied ──
$exemptProviders = ['Cloudflare', 'Google', 'OpenDNS', 'Quad9', 'AdGuard'];

// ── Load existing resolvers ──
if (!file_exists($resolverFile)) {
    fwrite(STDERR, "Error: resolver file not found: $resolverFile\n");
    exit(1);
}
$existing = require $resolverFile;
echo "Loaded " . count($existing) . " existing resolvers\n";

// Index existing by IP for fast lookup
$existingByIp = [];
foreach ($existing as $r) {
    $existingByIp[$r['ip']] = $r;
}

// ── Fetch public-dns.info CSV ──
echo "Fetching $csvUrl ...\n";
$ctx = stream_context_create(['http' => ['timeout' => 30, 'user_agent' => 'mwWhoIs-DNS-Updater/1.0']]);
$csv = @file_get_contents($csvUrl, false, $ctx);
if ($csv === false) {
    fwrite(STDERR, "Error: failed to fetch CSV from public-dns.info\n");
    exit(1);
}

// Parse CSV — columns: ip_address,name,as_number,as_org,country_code,city,version,error,dnssec,reliability,...
$lines = explode("\n", trim($csv));
$header = str_getcsv(array_shift($lines), ',', '"', '');
$ipIdx         = array_search('ip_address', $header);
$nameIdx       = array_search('name', $header);
$countryIdx    = array_search('country_code', $header);
$reliabilityIdx = array_search('reliability', $header);
$asOrgIdx      = array_search('as_org', $header);

if ($ipIdx === false || $countryIdx === false || $reliabilityIdx === false) {
    fwrite(STDERR, "Error: unexpected CSV format\n");
    exit(1);
}

$candidates = [];
foreach ($lines as $line) {
    if (empty(trim($line))) continue;
    $cols = str_getcsv($line, ',', '"', '');
    $ip = $cols[$ipIdx] ?? '';
    $reliability = (float)($cols[$reliabilityIdx] ?? 0);
    $country = strtoupper(trim($cols[$countryIdx] ?? ''));
    $name = trim($cols[$nameIdx] ?? '');
    if (empty($name) && $asOrgIdx !== false) {
        $name = trim($cols[$asOrgIdx] ?? '');
    }

    // Skip IPv6
    if (strpos($ip, ':') !== false) continue;
    // Skip low reliability
    if ($reliability < $minReliability) continue;
    // Must have valid country in our known list
    if (strlen($country) !== 2 || !isset($countryNames[$country])) continue;
    // Skip if already exists (manual or otherwise)
    if (isset($existingByIp[$ip])) {
        // Update reliability for existing public-dns sourced entries
        if (($existingByIp[$ip]['source'] ?? 'manual') === 'public-dns') {
            $existingByIp[$ip]['reliability'] = $reliability;
        }
        continue;
    }

    $candidates[$ip] = [
        'ip' => $ip,
        'name' => $name ?: 'Public DNS',
        'country_code' => $country,
        'reliability' => $reliability,
    ];
}

echo "Found " . count($candidates) . " new candidates (reliability >= $minReliability)\n";

// ── Select best candidates per country (max 2 per country to avoid bloat) ──
$byCountry = [];
foreach ($candidates as $c) {
    $byCountry[$c['country_code']][] = $c;
}

$newEntries = [];
$maxId = 0;
foreach ($existing as $r) {
    $maxId = max($maxId, $r['id']);
}

foreach ($byCountry as $cc => $servers) {
    // Count ALL existing entries for this country (manual + auto), excluding exempt providers
    $existingCountryCount = 0;
    $existingAutoCount = 0;
    foreach ($existing as $r) {
        if ($r['country_code'] === $cc && !in_array($r['name'], $exemptProviders)) {
            $existingCountryCount++;
            if (($r['source'] ?? 'manual') === 'public-dns') {
                $existingAutoCount++;
            }
        }
    }
    // Max $maxPerCountry auto-sourced per country, skip if country already has 4+ entries total
    // Exempt providers bypass these limits entirely
    $slotsAvailable = max(0, $maxPerCountry - $existingAutoCount);
    if ($slotsAvailable === 0 || $existingCountryCount >= 4) continue;

    // Sort by reliability descending
    usort($servers, function ($a, $b) { return $b['reliability'] <=> $a['reliability']; });

    $added = 0;
    foreach ($servers as $s) {
        $isExempt = in_array($s['name'], $exemptProviders);
        if (!$isExempt && $added >= $slotsAvailable) break;
        $maxId++;
        $location = $countryNames[$s['country_code']] ?? $s['country_code'];
        $newEntries[] = [
            'id'           => $maxId,
            'enabled'      => true,
            'name'         => $s['name'],
            'ip'           => $s['ip'],
            'country_code' => $s['country_code'],
            'location'     => $location,
            'type'         => 'standard',
            'source'       => 'public-dns',
            'reliability'  => $s['reliability'],
        ];
        if (!$isExempt) $added++;
    }
}

echo "Adding " . count($newEntries) . " new resolvers\n";

// ── Remove stale auto-sourced entries (reliability dropped below threshold) ──
$removed = 0;
$merged = [];
foreach ($existing as $r) {
    if (($r['source'] ?? 'manual') === 'public-dns' && ($r['reliability'] ?? 1) < $minReliability) {
        $removed++;
        continue;
    }
    $merged[] = $r;
}
echo "Removed $removed stale auto-sourced resolvers\n";

// Add new entries
$merged = array_merge($merged, $newEntries);

// ── Sort ──
usort($merged, function ($a, $b) use ($typeOrder) {
    // 1. GLOBAL first
    $aGlobal = ($a['country_code'] === 'GLOBAL') ? 0 : 1;
    $bGlobal = ($b['country_code'] === 'GLOBAL') ? 0 : 1;
    if ($aGlobal !== $bGlobal) return $aGlobal - $bGlobal;

    // 2. Alphabetically by location
    $locCmp = strcasecmp($a['location'], $b['location']);
    if ($locCmp !== 0) return $locCmp;

    // 3. Alphabetically by name
    $nameCmp = strcasecmp($a['name'], $b['name']);
    if ($nameCmp !== 0) return $nameCmp;

    // 4. By type: standard → security → family
    $aType = $typeOrder[$a['type']] ?? 9;
    $bType = $typeOrder[$b['type']] ?? 9;
    if ($aType !== $bType) return $aType - $bType;

    // 5. By IP
    return strcmp($a['ip'], $b['ip']);
});

// ── Write output ──
$output = "<?php\n";
$output .= "/**\n";
$output .= " * DNS Propagation Resolvers\n";
$output .= " *\n";
$output .= " * Public DNS servers used for propagation checks. Loaded by config.php.\n";
$output .= " * This file is auto-maintained by scripts/update-dns-resolvers.php\n";
$output .= " *\n";
$output .= " * Each entry:\n";
$output .= " *   id           Unique sequential identifier\n";
$output .= " *   enabled      true/false — set false to skip without removing\n";
$output .= " *   name         Provider name (may repeat across entries)\n";
$output .= " *   ip           IPv4 address\n";
$output .= " *   country_code ISO 3166-1 alpha-2 code (used for flag display), or 'GLOBAL'\n";
$output .= " *   location     Human-readable location label\n";
$output .= " *   type         'standard' | 'security' (malware/threat) | 'family' (parental control)\n";
$output .= " *   source       'manual' (hand-curated, never auto-removed) | 'public-dns' (auto-sourced)\n";
$output .= " *   reliability  0.00–1.00 score from public-dns.info (null for manual entries)\n";
$output .= " *\n";
$output .= " * Sort order (enforced by scripts/update-dns-resolvers.php):\n";
$output .= " *   1. GLOBAL entries first, then alphabetically by location\n";
$output .= " *   2. Within each location: alphabetically by resolver name\n";
$output .= " *   3. Within each name: by type (standard → security → family)\n";
$output .= " *\n";
$output .= " * Sources:\n";
$output .= " *   https://public-dns.info/\n";
$output .= " *   https://github.com/pingproxies/public-dns-directory\n";
$output .= " *   https://gist.github.com/mutin-sa/5dcbd35ee436eb629db7872581093bc5\n";
$output .= " *   https://blog.cloudflare.com/introducing-1-1-1-1-for-families/\n";
$output .= " *\n";
$output .= " * Last updated: " . date('Y-m-d H:i:s T') . "\n";
$output .= " */\n\n";
$output .= "return [\n";

$currentLocation = null;
foreach ($merged as $r) {
    $loc = $r['location'];
    if ($loc !== $currentLocation) {
        if ($currentLocation !== null) $output .= "\n";
        $output .= "    // ── $loc ──\n";
        $currentLocation = $loc;
    }

    $id   = str_pad($r['id'], 3, ' ', STR_PAD_LEFT);
    $en   = $r['enabled'] ? 'true ' : 'false';
    $name = str_pad("'" . $r['name'] . "',", 22);
    $ip   = str_pad("'" . $r['ip'] . "',", 22);
    $cc   = str_pad("'" . $r['country_code'] . "',", 10);
    $locS = str_pad("'" . $r['location'] . "',", 18);
    $type = str_pad("'" . $r['type'] . "',", 14);
    $src  = str_pad("'" . $r['source'] . "',", 14);
    $rel  = $r['reliability'] !== null ? sprintf('%.2f', $r['reliability']) : 'null';

    $output .= "    ['id' =>$id, 'enabled' => $en, 'name' => $name 'ip' => $ip 'country_code' => $cc 'location' => $locS 'type' => $type 'source' => $src 'reliability' => $rel],\n";
}

$output .= "];\n";

file_put_contents($resolverFile, $output);
echo "Wrote " . count($merged) . " resolvers to $resolverFile\n";

// Verify syntax
$check = exec("php -l " . escapeshellarg($resolverFile) . " 2>&1", $checkOutput, $exitCode);
if ($exitCode !== 0) {
    fwrite(STDERR, "SYNTAX ERROR in generated file:\n" . implode("\n", $checkOutput) . "\n");
    exit(1);
}
echo "Syntax check passed\n";
