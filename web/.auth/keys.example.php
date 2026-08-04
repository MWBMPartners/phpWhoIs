<?php

/**
 * mwWhoIs (DomainCheckr) — Secret API Keys (EXAMPLE)
 *
 * Copy this file to keys.php and fill in your real values:
 *
 *   cp web/.auth/keys.example.php web/.auth/keys.php
 *
 * keys.php is gitignored and is NEVER committed. On the server, this
 * web/.auth/ directory sits ABOVE the deployed web root (a sibling of
 * public_html/), so it is not reachable over HTTP even without the
 * .htaccess guard alongside this file.
 *
 * Loaded by web/public_html/includes/config.php, which falls back to
 * empty strings for any key that isn't present here — so every
 * integration simply stays dormant until you provide a key.
 *
 * USAGE (do not edit config.php's loader — just fill in the values below):
 *   return [ 'virustotal_api_key' => 'xxxxxxxx...', ... ];
 */

return [

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

    // Website Screenshot — works without a key (basic/free tier); provide one
    // to unlock higher resolution, rate limits, or premium features.
    'screenshot_api_key' => '',

    // Reserved for a future debug/diagnostics gate (e.g. verbose error output
    // or an internal-only endpoint). Currently unused — leave empty.
    'debug_key' => '',

];
