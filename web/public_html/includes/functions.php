<?php
/**
 * mwWhoIs — Core functions.
 * Extracted from lookup.php for testability.
 * (C) 2024 MWBM Partners Ltd (t/a MWservices)
 */

// ═══════════════════════════════════════════════════════════════════
//  Subprocess timeout helper (Issue #187)
// ═══════════════════════════════════════════════════════════════════

/**
 * Run a shell command with a hard wall-clock timeout, portably.
 * Prefers the `timeout` binary when present; falls back to proc_open + stream_select
 * (macOS / hosts without GNU coreutils). Returns command output, or null on failure/timeout-with-no-output.
 */
function runCommandWithTimeout(string $cmd, int $timeoutSec = 8): ?string {
    static $hasTimeout = null;
    if ($hasTimeout === null) {
        $hasTimeout = (bool) @shell_exec('command -v timeout 2>/dev/null');
    }
    if ($hasTimeout) {
        $out = @shell_exec('timeout ' . (int)$timeoutSec . ' ' . $cmd . ' 2>&1');
        return ($out === null || $out === '') ? null : $out;
    }
    $proc = @proc_open($cmd . ' 2>&1', [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) { return null; }
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $out = '';
    $deadline = microtime(true) + $timeoutSec;
    while (microtime(true) < $deadline) {
        $status = proc_get_status($proc);
        $out .= (string) stream_get_contents($pipes[1]);
        if (!$status['running']) { break; }
        $r = [$pipes[1]]; $w = null; $e = null;
        @stream_select($r, $w, $e, 0, 200000);
    }
    $status = proc_get_status($proc);
    if (!empty($status['running'])) { @proc_terminate($proc, 9); }
    foreach ($pipes as $p) { if (is_resource($p)) { @fclose($p); } }
    @proc_close($proc);
    return $out === '' ? null : $out;
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP fetch with a HARD total timeout (Issue #192)
// ═══════════════════════════════════════════════════════════════════

/**
 * GET a URL with a HARD total timeout via curl. Returns body string, or null on failure.
 *
 * Issue #197: pass $opts['resolve'] (a CURLOPT_RESOLVE-shaped array, e.g.
 * ["host:443:1.2.3.4", "host:80:1.2.3.4"]) to pin the connection to a pre-vetted IP
 * when $url's host is user-controlled. Callers MUST vet the host with
 * resolveAndVetHost() first — this function does not vet, it only pins.
 */
function httpFetch(string $url, array $opts = []): ?string {
    if (!function_exists('curl_init')) {
        // Issue #197: without curl we have no way to pin the connection to a pre-vetted
        // IP, so a caller that requires pinning would otherwise silently fall back to an
        // unpinned lookup (re-opening the DNS-rebinding window). Fail closed instead.
        if (!empty($opts['resolve'])) {
            return null;
        }
        // Fallback: stream context (idle timeout is the best we can do without curl)
        $ctx = stream_context_create(['http' => ['timeout' => $opts['timeout'] ?? 4, 'method' => $opts['method'] ?? 'GET', 'header' => $opts['header'] ?? "User-Agent: mwWhoIs\r\n", 'follow_location' => 0], 'ssl' => ['verify_peer' => false, 'verify_peer_name' => false]]);
        $r = @file_get_contents($url, false, $ctx);
        return $r === false ? null : $r;
    }
    $ch = curl_init($url);
    $curlOpts = [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => $opts['timeout'] ?? 4,      // TOTAL time cap
        CURLOPT_CONNECTTIMEOUT => $opts['connect'] ?? 2,
        CURLOPT_FOLLOWLOCATION => false,                       // do not auto-follow (SSRF-safe)
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT      => $opts['ua'] ?? 'mwWhoIs',
        CURLOPT_MAXFILESIZE    => $opts['maxbytes'] ?? 3145728, // 3 MB default cap
    ];
    // Issue #197: restrict redirects/requests to HTTP(S) only where curl supports it.
    if (defined('CURLOPT_PROTOCOLS')) { $curlOpts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
    if (defined('CURLOPT_REDIR_PROTOCOLS')) { $curlOpts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
    if (!empty($opts['resolve'])) { $curlOpts[CURLOPT_RESOLVE] = $opts['resolve']; }
    curl_setopt_array($ch, $curlOpts);
    if (!empty($opts['post'])) { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $opts['post']); }
    if (!empty($opts['headers'])) { curl_setopt($ch, CURLOPT_HTTPHEADER, $opts['headers']); }
    $r = curl_exec($ch);
    curl_close($ch);
    return ($r === false || $r === '') ? null : $r;
}


// ═══════════════════════════════════════════════════════════════════
//  SSRF egress gate (Issue #197)
// ═══════════════════════════════════════════════════════════════════
//
//  lookup.php makes many OUTBOUND connections to a user-supplied domain
//  (SSL probe, header audit, redirect-chain walk, tech-stack sniff, robots.txt
//  fetch, SMTP banner grab, ...). isValidDomain() only checks *format* — it says
//  nothing about where the name actually resolves. An attacker can point a
//  syntactically valid domain (or a wildcard-DNS service like nip.io/sslip.io)
//  at cloud metadata (169.254.169.254), loopback, or an internal RFC1918 host and
//  have this server fetch it on their behalf and reflect the response back — SSRF.
//
//  Policy: BLOCK private/reserved/internal ranges; public domains keep working
//  exactly as before. Every fetcher that connects to the user's host (not the
//  fixed third-party threat-intel APIs, which take the domain/IP as a query
//  parameter, not a connection target) must call resolveAndVetHost() first and
//  connect ONLY to the returned, pre-vetted IP (curl: CURLOPT_RESOLVE; sockets:
//  connect to the IP directly) — never re-resolve the hostname after vetting it,
//  or a DNS-rebinding attacker can swap the answer between the check and the use.

/**
 * CIDR ranges that must NEVER be treated as a safe SSRF target, even though some of
 * them (CGNAT, the IETF protocol/benchmarking/documentation ranges, multicast, the
 * NAT64 well-known prefix) are not reliably excluded by
 * FILTER_FLAG_NO_PRIV_RANGE|FILTER_FLAG_NO_RES_RANGE across PHP builds/versions.
 * Kept as an explicit list (rather than trusting the flags alone) so the policy is
 * self-documenting and doesn't silently change if that flag behaviour ever does.
 *
 * @return string[]
 */
function ssrfBlockedRanges(): array {
    return [
        // ── IPv4 ──
        '0.0.0.0/8',        // "this" network
        '10.0.0.0/8',       // RFC1918 private
        '100.64.0.0/10',    // CGNAT (RFC6598)
        '127.0.0.0/8',      // loopback
        '169.254.0.0/16',   // link-local — includes the 169.254.169.254 cloud metadata IP
        '172.16.0.0/12',    // RFC1918 private
        '192.168.0.0/16',   // RFC1918 private
        '192.0.0.0/24',     // IETF protocol assignments
        '192.0.2.0/24',     // TEST-NET-1
        '198.18.0.0/15',    // benchmarking
        '198.51.100.0/24',  // TEST-NET-2
        '203.0.113.0/24',   // TEST-NET-3
        '224.0.0.0/4',      // multicast
        '240.0.0.0/4',      // reserved / future use
        // ── IPv6 ──
        '::1/128',          // loopback
        '::/128',           // unspecified
        'fc00::/7',         // unique local address (ULA)
        'fe80::/10',        // link-local
        '::ffff:0:0/96',    // IPv4-mapped IPv6 — reject the mapped literal outright rather
                             // than unwrap-and-recheck the embedded v4; no legitimate public
                             // AAAA record is ever published in this form, it's only ever
                             // seen as a validator-bypass trick.
        '2001:db8::/32',    // documentation
        '64:ff9b::/96',     // NAT64 well-known prefix (can front an internal v4 host)
        // Security review (Issue #197): FILTER_FLAG_NO_PRIV_RANGE/NO_RES_RANGE only
        // recognise the IPv4-mapped form (::ffff:a.b.c.d) as embedding a v4 address —
        // NOT the deprecated "IPv4-compatible" form (::a.b.c.d, i.e. the last 32 bits of
        // an otherwise-zero address, equivalently written in hex groups e.g. "::7f00:1"
        // for 127.0.0.1, or "::a9fe:a9fe" for the 169.254.169.254 metadata address).
        // filter_var() with those flags does NOT reject "::7f00:1", even though it
        // decodes (via inet_pton) to the exact same 16 bytes as "::127.0.0.1", which IS
        // rejected — a pure notation difference. Block the whole /96 explicitly so no
        // hex-group spelling of a private v4 address can sneak past isPublicIp().
        '::/96',            // deprecated IPv4-compatible IPv6 (RFC4291) — embeds an arbitrary v4
        '2002::/16',         // 6to4 (RFC3056) — also embeds an arbitrary v4 in the address
    ];
}

/**
 * Is $ip inside $cidr? Works for both IPv4 and IPv6 (family must match).
 */
function cidrMatch(string $ip, string $cidr): bool {
    if (strpos($cidr, '/') === false) {
        return $ip === $cidr;
    }
    [$subnet, $bits] = explode('/', $cidr, 2);
    $bits = (int) $bits;

    $ipBin = @inet_pton($ip);
    $subnetBin = @inet_pton($subnet);
    if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
        return false; // different address family, or unparsable
    }

    $fullBytes = intdiv($bits, 8);
    $remBits = $bits % 8;

    if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($subnetBin, 0, $fullBytes)) {
        return false;
    }
    if ($remBits > 0) {
        $mask = chr((0xFF << (8 - $remBits)) & 0xFF);
        if ((substr($ipBin, $fullBytes, 1) & $mask) !== (substr($subnetBin, $fullBytes, 1) & $mask)) {
            return false;
        }
    }
    return true;
}

/**
 * Is $ip safe to connect to as an SSRF target — i.e. a global-scope PUBLIC address?
 * Returns false for anything private/reserved/loopback/link-local/metadata/multicast
 * (v4 or v6). Fails CLOSED: anything that isn't affirmatively a valid, public IP is
 * rejected.
 */
function isPublicIp(string $ip): bool {
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return false;
    }
    // Base filter: PHP's own private/reserved-range detector.
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    // Explicit belt-and-braces ranges the flags don't reliably cover (see ssrfBlockedRanges()).
    foreach (ssrfBlockedRanges() as $cidr) {
        if (cidrMatch($ip, $cidr)) {
            return false;
        }
    }
    return true;
}

/**
 * Resolve $host (a domain name OR an IP literal) and vet EVERY resulting address.
 *
 * Returns null (UNSAFE — do not connect) when:
 *   - $host doesn't resolve at all, or
 *   - ANY resolved A/AAAA answer is not a global-scope public address (rebinding
 *     defence: a multi-answer response is rejected wholesale if even one answer is
 *     private/internal, since an attacker can put a public IP first and a private
 *     one second, or vice versa across two lookups).
 *
 * On success returns ['host' => $host, 'ip' => <first vetted public IP>,
 * 'ips' => <all vetted public IPs>] so the caller can PIN its connection to a
 * specific, already-checked IP instead of letting the underlying transport
 * re-resolve $host (which would reopen the DNS-rebinding window between check and use).
 */
function resolveAndVetHost(string $host): ?array {
    static $cache = [];
    if (array_key_exists($host, $cache)) {
        return $cache[$host];
    }

    $ips = [];
    if (filter_var($host, FILTER_VALIDATE_IP)) {
        $ips[] = $host;
    } else {
        $aRecords = @dns_get_record($host, DNS_A);
        if ($aRecords) {
            foreach ($aRecords as $rec) {
                if (!empty($rec['ip'])) { $ips[] = $rec['ip']; }
            }
        }
        $aaaaRecords = @dns_get_record($host, DNS_AAAA);
        if ($aaaaRecords) {
            foreach ($aaaaRecords as $rec) {
                if (!empty($rec['ipv6'])) { $ips[] = $rec['ipv6']; }
            }
        }
    }

    $ips = array_values(array_unique($ips));

    if (empty($ips)) {
        return $cache[$host] = null; // doesn't resolve
    }
    foreach ($ips as $ip) {
        if (!isPublicIp($ip)) {
            return $cache[$host] = null; // at least one answer is private/internal — reject all
        }
    }

    return $cache[$host] = ['host' => $host, 'ip' => $ips[0], 'ips' => $ips];
}

/**
 * Bracket an IPv6 literal for use in a "host:port" style connection target
 * (ssl://, CURLOPT_RESOLVE, fsockopen, openssl s_client -connect). No-op for IPv4.
 */
function bracketIp(string $ip): string {
    return (strpos($ip, ':') !== false) ? '[' . $ip . ']' : $ip;
}

/**
 * Resolve a Location header value against the URL it was returned for. Handles
 * absolute URLs, protocol-relative ("//host/path"), and root-relative ("/path")
 * forms — good enough for the redirect targets real HTTP servers send.
 */
function resolveRedirectUrl(string $baseScheme, string $baseHost, string $location): string {
    if (preg_match('#^https?://#i', $location)) {
        return $location;
    }
    if (str_starts_with($location, '//')) {
        return $baseScheme . ':' . $location;
    }
    if (str_starts_with($location, '/')) {
        return $baseScheme . '://' . $baseHost . $location;
    }
    return $baseScheme . '://' . $baseHost . '/' . ltrim($location, './');
}

/**
 * Fetch $url via curl, pinning EVERY hop's connection to its own freshly-vetted IP and
 * manually following redirects ourselves (CURLOPT_FOLLOWLOCATION is never used here —
 * if it were, curl would connect straight to whatever host the Location header names
 * with NO vetting at all, which would silently defeat the whole gate on the very first
 * 3xx response). Each hop re-runs resolveAndVetHost() on its own host before connecting.
 *
 * Returns null if the initial host (or any hop along the way) fails vetting, if the
 * hop budget is exceeded while still redirecting, or if the transfer fails outright.
 * On success returns ['url' => <final URL>, 'status' => <final HTTP code>,
 * 'headers' => <raw header block of the final hop>, 'body' => <final hop response body>].
 *
 * $curlOpts are merged in as the base options (e.g. CURLOPT_NOBODY, CURLOPT_TIMEOUT,
 * CURLOPT_USERAGENT) — FOLLOWLOCATION/RESOLVE/HEADER are always forced by this helper.
 *
 * Security note: CURLOPT_RESOLVE pins are host:PORT-scoped — they only cover 80/443
 * below. A redirect to any other port would make curl fall back to a LIVE DNS lookup
 * for that host:port pair (confirmed against curl directly), completely bypassing the
 * pin and reopening the rebinding window. So any hop whose URL names a port other than
 * the implicit default 80/443 is rejected outright rather than connected to.
 */
function fetchViaVettedCurl(string $url, array $curlOpts = [], int $maxHops = 3): ?array {
    if (!function_exists('curl_init')) {
        return null;
    }
    for ($hop = 0; $hop <= $maxHops; $hop++) {
        $host = parse_url($url, PHP_URL_HOST);
        $scheme = parse_url($url, PHP_URL_SCHEME) ?: 'https';
        $port = parse_url($url, PHP_URL_PORT);
        if (!$host) {
            return null;
        }
        if ($port !== null && !in_array((int) $port, [80, 443], true)) {
            return null; // non-standard port — our CURLOPT_RESOLVE pin can't cover it safely
        }
        $vet = resolveAndVetHost($host);
        if ($vet === null) {
            return null; // unresolvable, or resolves to a private/internal address — stop
        }
        $ip = $vet['ip'];

        $ch = curl_init($url);
        $opts = $curlOpts;
        $opts[CURLOPT_RETURNTRANSFER] = true;
        $opts[CURLOPT_HEADER] = true;
        $opts[CURLOPT_FOLLOWLOCATION] = false;
        $opts[CURLOPT_RESOLVE] = [$host . ':443:' . bracketIp($ip), $host . ':80:' . bracketIp($ip)];
        if (defined('CURLOPT_PROTOCOLS')) { $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) { $opts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
        curl_setopt_array($ch, $opts);
        $raw = curl_exec($ch);
        if ($raw === false) {
            curl_close($ch);
            return null;
        }
        $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        $rawHeaders = substr($raw, 0, $headerSize);
        $body = substr($raw, $headerSize);

        $location = null;
        foreach (preg_split('/\r\n|\n/', trim($rawHeaders)) as $line) {
            if (preg_match('/^location:\s*(.+)/i', $line, $m)) {
                $location = trim($m[1]);
            }
        }

        if ($status >= 300 && $status < 400 && $location) {
            $url = resolveRedirectUrl($scheme, $host, $location);
            continue; // next loop iteration re-vets the NEW host before connecting
        }

        return ['url' => $url, 'status' => $status, 'headers' => $rawHeaders, 'body' => $body];
    }
    return null; // exceeded hop budget while still redirecting
}


// ═══════════════════════════════════════════════════════════════════
//  SSRF-safe curl_multi batch helper (Issue #196 Step 2)
//
//  Runs several outbound HTTP requests CONCURRENTLY via curl_multi, while
//  preserving every #197 SSRF invariant for EVERY handle in the batch:
//  redirects are never auto-followed, only http(s) is ever dialled, only
//  ports 80/443 are ever dialled, and — for any request whose host is
//  user-controlled — the connection is pinned to a pre-vetted IP via
//  CURLOPT_RESOLVE, exactly like fetchViaVettedCurl()/httpFetch() already do
//  for the single-request paths. Callers targeting a FIXED third-party API
//  host (not user-controlled — e.g. safebrowsing.googleapis.com,
//  virustotal.com, api.shodan.io, ip-api.com) omit 'pin_ip' and curl resolves
//  the host normally, exactly like httpFetch()/checkVirusTotal() etc. do
//  today; callers targeting the user-supplied lookup domain/host itself MUST
//  call resolveAndVetHost() first and pass the vetted IP as 'pin_ip'.
//
//  Modelled on the curl_multi_exec()/curl_multi_select() loop
//  checkAlternativeTldAvailability() already uses (Issue #196 plan).
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the CURLOPT_* option set for ONE request in a curlMultiBatch() batch —
 * a PURE function (no curl handle, no I/O) so the SSRF invariants can be
 * asserted on directly in unit tests without a network round-trip.
 *
 * $req: ['url' => string, 'pin_ip' => ?string, 'post' => ?string, 'headers' => ?array]
 *
 * Returns ['ok' => true, 'opts' => array] when the request is safe to open,
 * or ['ok' => false, 'error' => string] when it must be REJECTED outright —
 * the caller (curlMultiBatch()) must never open a connection for a rejected
 * request.
 *
 * Rejected when:
 *   - the URL doesn't parse to a host + scheme at all;
 *   - the scheme isn't http/https;
 *   - the (explicit, or scheme-default) port isn't 80/443 — mirrors
 *     fetchViaVettedCurl()'s port restriction, since a CURLOPT_RESOLVE pin
 *     (or the bare-IP-literal check below) only ever covers the standard
 *     ports;
 *   - a 'pin_ip' was supplied but fails isPublicIp() — the caller vetted a
 *     host that turned out to be private/reserved, or passed a bad value;
 *   - NO 'pin_ip' was supplied AND the URL's host is itself a raw IP literal
 *     that fails isPublicIp() — an unpinned request has no vetting at all, so
 *     a literal private/reserved/loopback/metadata IP target is refused
 *     outright rather than silently connected to. (A bare HOSTNAME with no
 *     pin_ip — e.g. a fixed third-party API host — is allowed through; it is
 *     the caller's responsibility, per the #197 contract, to only omit
 *     pin_ip for hosts that are NOT user-controlled.)
 */
function curlMultiHandleOpts(array $req): array {
    $url = $req['url'] ?? '';
    $host = parse_url($url, PHP_URL_HOST);
    $scheme = parse_url($url, PHP_URL_SCHEME);
    $port = parse_url($url, PHP_URL_PORT);

    if (!$host || !$scheme) {
        return ['ok' => false, 'error' => 'unparsable_url'];
    }
    if (!in_array(strtolower($scheme), ['http', 'https'], true)) {
        return ['ok' => false, 'error' => 'bad_scheme'];
    }
    $effectivePort = $port !== null ? (int) $port : (strtolower($scheme) === 'https' ? 443 : 80);
    if (!in_array($effectivePort, [80, 443], true)) {
        return ['ok' => false, 'error' => 'bad_port'];
    }

    // parse_url(PHP_URL_HOST) returns an IPv6 literal WITH its URL brackets
    // still attached (e.g. "[::1]"), which filter_var(..., FILTER_VALIDATE_IP)
    // does NOT recognise as a valid IP — strip them before validating, or a
    // bracketed private/reserved IPv6 literal URL (e.g. "http://[::1]/") would
    // silently fail the "is this host itself a private IP?" check below and
    // be let through unpinned, straight to curl.
    $hostForIpCheck = $host;
    if (strlen($hostForIpCheck) > 1 && $hostForIpCheck[0] === '[' && substr($hostForIpCheck, -1) === ']') {
        $hostForIpCheck = substr($hostForIpCheck, 1, -1);
    }

    $pinIp = $req['pin_ip'] ?? null;
    if ($pinIp !== null) {
        if (!isPublicIp($pinIp)) {
            return ['ok' => false, 'error' => 'private_ip'];
        }
    } elseif (filter_var($hostForIpCheck, FILTER_VALIDATE_IP) && !isPublicIp($hostForIpCheck)) {
        return ['ok' => false, 'error' => 'private_ip'];
    }

    $opts = [
        CURLOPT_URL            => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,     // never auto-follow (SSRF-safe — Issue #197)
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT      => 'mwWhoIs',
        CURLOPT_NOSIGNAL       => 1,
    ];
    if (defined('CURLOPT_PROTOCOLS')) { $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
    if (defined('CURLOPT_REDIR_PROTOCOLS')) { $opts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }

    if ($pinIp !== null) {
        $bracketed = bracketIp($pinIp);
        $opts[CURLOPT_RESOLVE] = [$host . ':443:' . $bracketed, $host . ':80:' . $bracketed];
    }

    if (!empty($req['post'])) {
        $opts[CURLOPT_POST] = true;
        $opts[CURLOPT_POSTFIELDS] = $req['post'];
    }
    if (!empty($req['headers'])) {
        $opts[CURLOPT_HTTPHEADER] = $req['headers'];
    }

    return ['ok' => true, 'opts' => $opts];
}

/**
 * Fire several HTTP requests concurrently via curl_multi, applying
 * curlMultiHandleOpts()'s SSRF gate to EVERY request before it is ever added
 * to the multi handle — a rejected request never opens a connection.
 *
 * $requests: key => ['url'=>string, 'pin_ip'=>?string, 'post'=>?string, 'headers'=>?array]
 * $totalTimeout: hard per-handle CURLOPT_TIMEOUT (seconds) AND the wall-clock
 *   cap on the whole multi loop (defence-in-depth on top of the per-handle
 *   timeout, in case curl_multi_select() ever undersleeps).
 *
 * Returns key => ['status'=>int, 'body'=>?string, 'errno'=>int] for EVERY key
 * in $requests:
 *   - a request curlMultiHandleOpts() rejected gets status=0, body=null,
 *     errno=-1 (never connected);
 *   - if curl_multi_init() doesn't exist at all, every request gets
 *     status=0, body=null, errno=-2 — callers MUST treat this the same as a
 *     transport failure and fall back to their serial code path, exactly
 *     like checkAlternativeTldAvailability() already falls back today when
 *     curl_multi_init isn't available.
 */
function curlMultiBatch(array $requests, int $totalTimeout = 8): array {
    $results = [];
    $pending = [];

    foreach ($requests as $key => $req) {
        $built = curlMultiHandleOpts($req);
        if (!$built['ok']) {
            $results[$key] = ['status' => 0, 'body' => null, 'errno' => -1];
            continue;
        }
        $pending[$key] = $built['opts'];
    }

    if (empty($pending)) {
        return $results; // nothing safe to run — no curl_multi_init() call at all
    }

    if (!function_exists('curl_multi_init')) {
        foreach ($pending as $key => $opts) {
            $results[$key] = ['status' => 0, 'body' => null, 'errno' => -2];
        }
        return $results;
    }

    $mh = curl_multi_init();
    $handles = [];
    foreach ($pending as $key => $opts) {
        $opts[CURLOPT_TIMEOUT] = $totalTimeout;
        $opts[CURLOPT_CONNECTTIMEOUT] = min(3, $totalTimeout);
        $ch = curl_init();
        curl_setopt_array($ch, $opts);
        curl_multi_add_handle($mh, $ch);
        $handles[$key] = $ch;
    }

    $deadline = microtime(true) + $totalTimeout;
    $running = null;
    do {
        $status = curl_multi_exec($mh, $running);
        if ($running) {
            curl_multi_select($mh, 0.5);
        }
    } while ($running > 0 && $status === CURLM_OK && microtime(true) < $deadline);

    foreach ($handles as $key => $ch) {
        $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno = curl_errno($ch);
        $body = curl_multi_getcontent($ch);
        curl_multi_remove_handle($mh, $ch);
        curl_close($ch);
        $results[$key] = [
            'status' => $httpCode,
            'body'   => ($body === '' || $body === false || $body === null) ? null : $body,
            'errno'  => $errno,
        ];
    }
    curl_multi_close($mh);

    return $results;
}


// ═══════════════════════════════════════════════════════════════════
//  Logging (Issue #43)
// ═══════════════════════════════════════════════════════════════════

/**
 * Log a message to the application error log.
 * Creates the logs directory if it doesn't exist.
 */
function appLog(string $message, string $level = 'ERROR'): void {
    $logDir = dirname(__DIR__) . DIRECTORY_SEPARATOR . 'logs';
    if (!is_dir($logDir)) {
        @mkdir($logDir, 0755, true);
    }

    $logFile = $logDir . DIRECTORY_SEPARATOR . 'error.log';
    $timestamp = date('Y-m-d H:i:s');
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'CLI';
    // Strip CR/LF from the message (Issue #203) so attacker-influenced input
    // logged verbatim (e.g. raw whois/RDAP output, a malformed domain) can't
    // inject fake extra log lines/entries.
    $safeMessage = str_replace(["\r", "\n"], ' ', $message);
    $entry = "[{$timestamp}] [{$level}] [{$ip}] {$safeMessage}" . PHP_EOL;

    @file_put_contents($logFile, $entry, FILE_APPEND | LOCK_EX);
}


// ═══════════════════════════════════════════════════════════════════
//  Domain ownership verification (Issue #64)
// ═══════════════════════════════════════════════════════════════════

/**
 * Generate a DNS verification token for domain ownership.
 * The token should be added as a TXT record at _mwwhois-verify.{domain}.
 *
 * @param  string $domain     The domain to verify
 * @param  string $sessionId  Session or user identifier
 * @return string             The verification token
 */
function generateVerificationToken(string $domain, string $sessionId): string {
    return 'mwwhois-verify=' . hash('sha256', $domain . $sessionId . 'mwwhois-salt');
}

/**
 * Check if a domain has the verification TXT record.
 *
 * @param  string $domain  The domain to verify
 * @param  string $token   The expected token value
 * @return bool            True if verified
 */
function verifyDomainOwnership(string $domain, string $token): bool {
    $records = @dns_get_record('_mwwhois-verify.' . $domain, DNS_TXT);
    if (!$records) {
        return false;
    }

    foreach ($records as $record) {
        if (isset($record['txt']) && trim($record['txt']) === $token) {
            return true;
        }
    }

    return false;
}


// ═══════════════════════════════════════════════════════════════════
//  API key management (Issue #61)
// ═══════════════════════════════════════════════════════════════════

/**
 * Load API keys from storage.
 * Keys file format: { "key_hash": { "tier": "free|premium", "rate_limit": 30, "created": "...", "label": "..." } }
 */
function loadApiKeys(): array {
    if (!defined('CACHE_DIR')) {
        return [];
    }
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . 'api_keys.json';
    if (!file_exists($file)) {
        return [];
    }
    $keys = json_decode(file_get_contents($file), true);
    return is_array($keys) ? $keys : [];
}

/**
 * Validate an API key and return its config, or null if invalid.
 */
function validateApiKey(string $key): ?array {
    $keys = loadApiKeys();
    $hash = hash('sha256', $key);
    return isset($keys[$hash]) ? $keys[$hash] : null;
}

/**
 * Get rate limit for an API key tier.
 */
function getApiKeyRateLimit(?array $keyConfig): int {
    if (!$keyConfig) {
        return RATE_LIMIT_MAX; // Default: 30/min
    }
    return isset($keyConfig['rate_limit']) ? (int)$keyConfig['rate_limit'] : RATE_LIMIT_MAX;
}


// ═══════════════════════════════════════════════════════════════════
//  Lookup statistics tracking (Issue #60)
// ═══════════════════════════════════════════════════════════════════

function trackLookup(string $type, string $domain = ''): void {
    if (!defined('CACHE_DIR')) {
        return;
    }
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . 'lookup_stats.json';
    $stats = file_exists($file) ? json_decode(file_get_contents($file), true) : [];
    // Issue #218: a truncated/corrupted stats file shouldn't be treated as
    // valid data — reset to defaults rather than risk array-access errors
    // below on a non-array $stats.
    if (!is_array($stats)) {
        $stats = ['total' => 0, 'cache_hits' => 0, 'rdap' => 0, 'whois' => 0, 'errors' => 0, 'popular_domains' => []];
    }

    $stats['total'] = ($stats['total'] ?? 0) + 1;
    if ($type === 'cache_hit') {
        $stats['cache_hits'] = ($stats['cache_hits'] ?? 0) + 1;
    }
    if ($type === 'rdap') {
        $stats['rdap'] = ($stats['rdap'] ?? 0) + 1;
    }
    if ($type === 'whois') {
        $stats['whois'] = ($stats['whois'] ?? 0) + 1;
    }
    if ($type === 'error') {
        $stats['errors'] = ($stats['errors'] ?? 0) + 1;
    }

    if ($domain) {
        if (!isset($stats['popular_domains'])) {
            $stats['popular_domains'] = [];
        }
        $stats['popular_domains'][$domain] = ($stats['popular_domains'][$domain] ?? 0) + 1;
        arsort($stats['popular_domains']);
        $stats['popular_domains'] = array_slice($stats['popular_domains'], 0, 100, true);
    }

    @file_put_contents($file, json_encode($stats), LOCK_EX);
}


// ═══════════════════════════════════════════════════════════════════
//  Security helpers
// ═══════════════════════════════════════════════════════════════════

function validateCsrfToken(): bool {
    if (empty($_POST['csrf_token']) || empty($_SESSION['csrf_token'])) {
        return false;
    }
    return hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
}

/**
 * Session-based rate limiting (per-user).
 */
function checkRateLimit(int $limit = RATE_LIMIT_MAX): bool {
    $now = time();

    if (!isset($_SESSION['rate_limit']) || ($now - $_SESSION['rate_limit']['start']) > RATE_LIMIT_WINDOW) {
        $_SESSION['rate_limit'] = ['count' => 0, 'start' => $now];
    }

    $_SESSION['rate_limit']['count']++;

    return $_SESSION['rate_limit']['count'] <= $limit;
}

/**
 * IP-based rate limiting (Issue #22).
 * Uses file-based storage in the cache directory.
 * Harder to bypass than session-based limiting.
 */
function checkIpRateLimit(int $limit = RATE_LIMIT_MAX): bool {
    // Use REMOTE_ADDR as primary (cannot be spoofed)
    // Only use X-Forwarded-For if behind a trusted proxy
    $ip = '';
    if (isset($_SERVER['REMOTE_ADDR'])) {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    $ip = trim($ip);
    if ($ip === '' || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return true;
    }

    $rateLimitDir = CACHE_DIR . DIRECTORY_SEPARATOR . 'rate_limits';
    if (!is_dir($rateLimitDir)) {
        @mkdir($rateLimitDir, 0755, true);
    }

    // Use hashed IP as filename (privacy + filesystem safety)
    $file = $rateLimitDir . DIRECTORY_SEPARATOR . md5($ip) . '.json';
    $now = time();
    $data = null;

    if (file_exists($file)) {
        $data = json_decode(file_get_contents($file), true);
    }

    // Reset if window expired or invalid/malformed data (Issue #218) — treat
    // a corrupted rate-limit file as a miss rather than trusting its shape.
    if (!is_array($data) || !isset($data['start']) || ($now - $data['start']) > RATE_LIMIT_WINDOW) {
        $data = ['count' => 0, 'start' => $now];
    }

    $data['count']++;
    file_put_contents($file, json_encode($data));

    // Clean up old rate limit files periodically (1 in 100 chance)
    if (rand(1, 100) === 1) {
        cleanExpiredRateLimits($rateLimitDir);
    }

    return $data['count'] <= $limit;
}

/**
 * Seconds remaining until the current (session-based) rate-limit window
 * resets — used for the `Retry-After` header on 429 responses (Issue #245).
 * Mirrors the X-RateLimit-Reset computation in lookup.php; checkRateLimit()
 * always populates $_SESSION['rate_limit']['start'] before this is called.
 */
function rateLimitRetryAfterSeconds(): int {
    if (isset($_SESSION['rate_limit']['start'])) {
        return max(1, ($_SESSION['rate_limit']['start'] + RATE_LIMIT_WINDOW) - time());
    }
    return RATE_LIMIT_WINDOW;
}

/**
 * Remove expired rate limit files.
 */
function cleanExpiredRateLimits(string $dir): void {
    $files = glob($dir . DIRECTORY_SEPARATOR . '*.json');
    if (!$files) {
        return;
    }

    $now = time();
    foreach ($files as $file) {
        $data = json_decode(file_get_contents($file), true);
        // Issue #218: treat a corrupted/malformed rate-limit file as stale too.
        if (!is_array($data) || !isset($data['start']) || ($now - $data['start']) > RATE_LIMIT_WINDOW * 2) {
            @unlink($file);
        }
    }
}

/**
 * Validate that input does not exceed maximum allowed size.
 * Prevents memory exhaustion from oversized POST data.
 */
function validateInputSize(): bool {
    $contentLength = 0;
    if (isset($_SERVER['CONTENT_LENGTH'])) {
        $contentLength = (int)$_SERVER['CONTENT_LENGTH'];
    }

    if ($contentLength > MAX_POST_SIZE) {
        return false;
    }

    return true;
}


// ═══════════════════════════════════════════════════════════════════
//  Result caching (Issue #57 — Redis/Memcached with file fallback)
// ═══════════════════════════════════════════════════════════════════

/**
 * Get a cache backend instance. Tries Redis, then Memcached, then falls back to file.
 * Returns: 'redis', 'memcached', or 'file'.
 */
function getCacheBackend() {
    static $backend = null;
    static $conn = null;

    if ($backend !== null) {
        return ['type' => $backend, 'conn' => $conn];
    }

    // Try Redis
    if (class_exists('Redis')) {
        try {
            $redis = new Redis();
            $host = defined('CACHE_REDIS_HOST') ? CACHE_REDIS_HOST : '127.0.0.1';
            $port = defined('CACHE_REDIS_PORT') ? CACHE_REDIS_PORT : 6379;
            if (@$redis->connect($host, $port, 1)) {
                $backend = 'redis';
                $conn = $redis;
                return ['type' => $backend, 'conn' => $conn];
            }
        } catch (\Exception $e) {
            // Fall through
        }
    }

    // Try Memcached
    if (class_exists('Memcached')) {
        try {
            $mc = new Memcached();
            $host = defined('CACHE_MEMCACHED_HOST') ? CACHE_MEMCACHED_HOST : '127.0.0.1';
            $port = defined('CACHE_MEMCACHED_PORT') ? CACHE_MEMCACHED_PORT : 11211;
            $mc->addServer($host, $port);
            // Test connection
            $mc->getVersion();
            if ($mc->getResultCode() === Memcached::RES_SUCCESS) {
                $backend = 'memcached';
                $conn = $mc;
                return ['type' => $backend, 'conn' => $conn];
            }
        } catch (\Exception $e) {
            // Fall through
        }
    }

    $backend = 'file';
    $conn = null;
    return ['type' => $backend, 'conn' => $conn];
}

function getCached(string $domain, int $ttl = CACHE_TTL): ?string {
    $cache = getCacheBackend();
    $key = 'mwwhois:' . md5($domain);

    if ($cache['type'] === 'redis') {
        $val = $cache['conn']->get($key);
        return $val !== false ? $val : null;
    }

    if ($cache['type'] === 'memcached') {
        $val = $cache['conn']->get($key);
        return $cache['conn']->getResultCode() === Memcached::RES_SUCCESS ? $val : null;
    }

    // File fallback
    $file = CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';

    if (!file_exists($file)) {
        return null;
    }

    $data = json_decode(file_get_contents($file), true);

    // Issue #218: guard against a truncated/corrupted cache file — treat
    // anything that isn't a well-formed {ts, result} array as a cache miss
    // rather than risking array-access errors on a non-array $data.
    if (!is_array($data) || !isset($data['ts'], $data['result']) || (time() - $data['ts']) >= $ttl) {
        return null;
    }

    return $data['result'];
}

function setCache(string $domain, string $result, int $ttl = CACHE_TTL): void {
    $cache = getCacheBackend();
    $key = 'mwwhois:' . md5($domain);

    if ($cache['type'] === 'redis') {
        $cache['conn']->setex($key, $ttl, $result);
        return;
    }

    if ($cache['type'] === 'memcached') {
        $cache['conn']->set($key, $result, $ttl);
        return;
    }

    // File fallback
    if (!is_dir(CACHE_DIR)) {
        @mkdir(CACHE_DIR, 0755, true);
    }

    $cacheFile = CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';
    file_put_contents($cacheFile, json_encode(['ts' => time(), 'result' => $result]));
}


// ═══════════════════════════════════════════════════════════════════
//  TLD & Second-Level Suffix Lists (auto-updating)
// ═══════════════════════════════════════════════════════════════════

/**
 * Updates both lists daily:
 *  1. IANA root zone TLDs (~25KB from data.iana.org)
 *  2. Second-level suffixes extracted from Mozilla PSL ICANN section (~5KB)
 */
function updateTldDataIfNeeded(): void {
    if (file_exists(TLD_META_PATH)) {
        $meta = json_decode(file_get_contents(TLD_META_PATH), true);
        if (isset($meta['checked_at']) && (time() - $meta['checked_at']) < 86400) {
            return;
        }
    }

    // Issue #193: this now runs off the request path (deferred to a shutdown function
    // that fires after the response has been flushed to the client), so concurrent
    // "first" requests could otherwise all race to fetch + overwrite the same files at
    // once. Guard with a non-blocking exclusive lock — if another process already holds
    // it, that process is already doing the refresh, so just bail out.
    $lockFile = TLD_META_PATH . '.lock';
    $lockHandle = @fopen($lockFile, 'c');
    if (!$lockHandle) {
        return;
    }
    if (!@flock($lockHandle, LOCK_EX | LOCK_NB)) {
        @fclose($lockHandle);
        return;
    }

    // Re-check under the lock — another process may have just finished the refresh
    // while we were waiting to acquire it.
    if (file_exists(TLD_META_PATH)) {
        $meta = json_decode(file_get_contents(TLD_META_PATH), true);
        if (isset($meta['checked_at']) && (time() - $meta['checked_at']) < 86400) {
            @flock($lockHandle, LOCK_UN);
            @fclose($lockHandle);
            return;
        }
    }

    $ctx = stream_context_create(['http' => ['timeout' => 5]]);
    $anySucceeded = false;

    // 1. Fetch IANA TLD list
    $tldResponse = @file_get_contents(IANA_TLD_URL, false, $ctx);
    if ($tldResponse !== false) {
        file_put_contents(IANA_TLD_PATH, $tldResponse);
        $anySucceeded = true;
    }

    // 2. Fetch Mozilla PSL → extract ICANN second-level suffixes only
    $pslResponse = @file_get_contents(PSL_ICANN_URL, false, $ctx);
    if ($pslResponse !== false) {
        $suffixes = extractSecondLevelSuffixes($pslResponse);
        file_put_contents(SL_SUFFIXES_PATH, implode("\n", $suffixes));
        $anySucceeded = true;
    }

    // Only stamp checked_at when at least one fetch succeeded — a failed first
    // fetch (e.g. a transient network hiccup) shouldn't lock in an empty state for
    // 24h; let the very next request try the refresh again.
    if ($anySucceeded) {
        file_put_contents(TLD_META_PATH, json_encode(['checked_at' => time()]));
    }

    @flock($lockHandle, LOCK_UN);
    @fclose($lockHandle);
}

/**
 * Parses the Mozilla PSL and extracts only multi-part ICANN suffixes
 * (e.g. co.uk, com.au) — ignores single TLDs and private domains.
 */
function extractSecondLevelSuffixes(string $pslContent): array {
    $suffixes = [];
    $inIcann = false;

    foreach (explode("\n", $pslContent) as $line) {
        $line = trim($line);

        if ($line === '// ===BEGIN ICANN DOMAINS===') {
            $inIcann = true;
            continue;
        }

        if ($line === '// ===END ICANN DOMAINS===') {
            break;
        }

        if (!$inIcann || $line === '' || str_starts_with($line, '//')) {
            continue;
        }

        // Only keep multi-part entries (contain a dot) — skip wildcard/negation entries
        if (str_contains($line, '.')  && !str_starts_with($line, '*') && !str_starts_with($line, '!')) {
            $suffixes[] = strtolower($line);
        }
    }

    return array_unique($suffixes);
}

function loadSecondLevelSuffixes(): array {
    if (!file_exists(SL_SUFFIXES_PATH)) {
        return [];
    }

    $lines = file(SL_SUFFIXES_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $trimmed = array_map('trim', $lines);

    return array_filter($trimmed, function($line) {
        return $line !== '';
    });
}

function extractRegistrableDomain(string $domain): string {
    $parts = explode('.', strtolower($domain));

    if (count($parts) <= 2) {
        return implode('.', $parts);
    }

    $suffixes = loadSecondLevelSuffixes();

    // Check longest match first (3-part, then 2-part suffixes)
    for ($len = min(3, count($parts) - 1); $len >= 2; $len--) {
        $candidate = implode('.', array_slice($parts, -$len));
        if (in_array($candidate, $suffixes)) {
            return implode('.', array_slice($parts, -($len + 1)));
        }
    }

    // Default: last two parts
    return implode('.', array_slice($parts, -2));
}


// ═══════════════════════════════════════════════════════════════════
//  IP / Reverse DNS (Issue #45)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check if input is an IP address (v4 or v6).
 */
function isIpAddress(string $input): bool {
    return filter_var($input, FILTER_VALIDATE_IP) ;
}

/**
 * Perform reverse DNS lookup for an IP address.
 * Returns PTR hostname or null.
 */
function reverseDnsLookup(string $ip): ?string {
    $hostname = gethostbyaddr($ip);
    if ($hostname === false || $hostname === $ip) {
        return null;
    }
    return $hostname;
}

/**
 * Get WHOIS info for an IP address.
 */
function ipWhoisLookup(string $ip): ?string {
    $escapedIp = escapeshellarg($ip);
    $result = runCommandWithTimeout("whois {$escapedIp}", 8);
    if ($result) {
        return $result;
    }
    return null;
}


// ═══════════════════════════════════════════════════════════════════
//  Domain input handling
// ═══════════════════════════════════════════════════════════════════

function sanitizeDomainInput(string $input): string {
    $input = trim($input);

    // Reject excessively long input
    if (strlen($input) > MAX_DOMAIN_LENGTH) {
        return '';
    }

    // Strip null bytes (injection vector)
    $input = str_replace("\0", '', $input);

    $input = filter_var($input, FILTER_SANITIZE_URL);

    $host = parse_url($input, PHP_URL_HOST);
    if (!$host) {
        $host = $input;
    }

    $host = preg_replace('/^www\./i', '', $host);

    return extractRegistrableDomain(strtolower($host));
}

function isValidDomain(string $domain): bool {
    // Length check
    if (strlen($domain) === 0 || strlen($domain) > MAX_DOMAIN_LENGTH) {
        return false;
    }

    // Must not contain shell-dangerous characters
    if (preg_match('/[;&|`$(){}\\\\<>\'"!#]/', $domain)) {
        return false;
    }

    // Standard domain format validation (no leading/trailing hyphens per label)
    return (bool) preg_match('/^(?!-)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/', $domain);
}


// ═══════════════════════════════════════════════════════════════════
//  Availability detection
// ═══════════════════════════════════════════════════════════════════

function detectAvailability(string $text): string {
    // Positive registration indicators take priority
    if (preg_match('/Registrar:\s*\S+/i', $text) ||
        preg_match('/Creat(?:ion|ed) Date:\s*\S+/i', $text) ||
        preg_match('/Registry Domain ID:\s*\S+/i', $text)) {
        return 'registered';
    }

    // Explicit "not found" patterns (anchored to start of line to avoid boilerplate matches)
    $patterns = [
        '/^No match for /mi',
        '/^NOT FOUND\b/mi',
        '/^No Data Found/mi',
        '/^No entries found/mi',
        '/^Domain not found/mi',
        '/^The queried object does not exist/mi',
        '/^This query returned 0 objects/mi',
        '/^Object does not exist/mi',
        '/^Status:\s*free\b/mi',
        '/^%% No entries found/mi',
    ];

    foreach ($patterns as $p) {
        if (preg_match($p, $text)) {
            return 'available';
        }
    }

    // Known WHOIS error signatures (Issue #216) — these mean the query failed,
    // not that the domain is registered, so surface them as 'unknown' instead
    // of falling through to the 'registered' default below.
    $errorPatterns = [
        '/network is unreachable/i',
        '/connection refused/i',
        '/no whois server/i',
        '/timed out/i',
        '/no route to host/i',
        '/quota exceeded/i',
        '/try again later/i',
    ];

    foreach ($errorPatterns as $p) {
        if (preg_match($p, $text)) {
            return 'unknown';
        }
    }

    return 'registered';
}


// ═══════════════════════════════════════════════════════════════════
//  DNS records
// ═══════════════════════════════════════════════════════════════════

function getDnsRecords(string $domain): array {
    $records = [];
    $typeMap = [
        DNS_A => 'A',
        DNS_AAAA => 'AAAA',
        DNS_MX => 'MX',
        DNS_NS => 'NS',
        DNS_TXT => 'TXT',
        DNS_CNAME => 'CNAME',
    ];

    foreach ($typeMap as $const => $name) {
        $result = @dns_get_record($domain, $const);

        if (!$result) {
            continue;
        }

        foreach ($result as $rec) {
            $entry = ['type' => $name, 'value' => ''];

            switch ($const) {
                case DNS_A:
                    if (isset($rec['ip'])) {
                        $entry['value'] = $rec['ip'];
                    }
                    break;
                case DNS_AAAA:
                    if (isset($rec['ipv6'])) {
                        $entry['value'] = $rec['ipv6'];
                    }
                    break;
                case DNS_MX:
                    if (isset($rec['target'])) {
                        $entry['value'] = $rec['target'];
                    }
                    if (isset($rec['pri'])) {
                        $entry['priority'] = $rec['pri'];
                    }
                    break;
                case DNS_NS:
                case DNS_CNAME:
                    if (isset($rec['target'])) {
                        $entry['value'] = $rec['target'];
                    }
                    break;
                case DNS_TXT:
                    if (isset($rec['txt'])) {
                        $entry['value'] = $rec['txt'];
                    }
                    break;
            }

            $records[] = $entry;
        }
    }

    return $records;
}

/**
 * Return the value of the first A record in a DNS record array (as produced
 * by getDnsRecords()), or null if there isn't one. Dedupes the several
 * copy-pasted "find the first A record to use as an IP" loops that used to
 * be scattered across lookup.php's enrichment pipeline (Issue #218).
 */
function firstARecord(array $dns): ?string {
    foreach ($dns as $rec) {
        if (($rec['type'] ?? null) === 'A' && !empty($rec['value'])) {
            return $rec['value'];
        }
    }
    return null;
}


// ═══════════════════════════════════════════════════════════════════
//  Email security check — DMARC/SPF/DKIM (Issue #56)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check email security posture by examining DNS TXT records.
 */
function checkEmailSecurity(string $domain): array {
    $result = [
        'spf' => ['found' => false, 'record' => null, 'status' => 'missing'],
        'dmarc' => ['found' => false, 'record' => null, 'status' => 'missing'],
        'dkim' => ['found' => false, 'status' => 'unknown'],
    ];

    // SPF — look in TXT records for the domain
    $txtRecords = @dns_get_record($domain, DNS_TXT);
    if ($txtRecords) {
        foreach ($txtRecords as $rec) {
            if (isset($rec['txt']) && str_starts_with(strtolower($rec['txt']), 'v=spf1')) {
                $result['spf']['found'] = true;
                $result['spf']['record'] = $rec['txt'];
                $result['spf']['status'] = 'configured';
                break;
            }
        }
    }

    // DMARC — look in TXT records for _dmarc.domain
    $dmarcRecords = @dns_get_record('_dmarc.' . $domain, DNS_TXT);
    if ($dmarcRecords) {
        foreach ($dmarcRecords as $rec) {
            if (isset($rec['txt']) && str_starts_with(strtolower($rec['txt']), 'v=dmarc1')) {
                $result['dmarc']['found'] = true;
                $result['dmarc']['record'] = $rec['txt'];

                // Check policy
                if (stripos($rec['txt'], 'p=reject') !== false) {
                    $result['dmarc']['status'] = 'strict (reject)';
                } elseif (stripos($rec['txt'], 'p=quarantine') !== false) {
                    $result['dmarc']['status'] = 'moderate (quarantine)';
                } elseif (stripos($rec['txt'], 'p=none') !== false) {
                    $result['dmarc']['status'] = 'monitor only (none)';
                } else {
                    $result['dmarc']['status'] = 'configured';
                }
                break;
            }
        }
    }

    // DKIM — check common selectors
    $dkimSelectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'k2', 'mail', 'dkim'];
    foreach ($dkimSelectors as $selector) {
        $dkimRecords = @dns_get_record($selector . '._domainkey.' . $domain, DNS_TXT);
        if ($dkimRecords) {
            foreach ($dkimRecords as $rec) {
                if (isset($rec['txt']) && stripos($rec['txt'], 'v=DKIM1') !== false) {
                    $result['dkim']['found'] = true;
                    $result['dkim']['selector'] = $selector;
                    $result['dkim']['status'] = 'configured (selector: ' . $selector . ')';
                    break 2;
                }
            }
        }
    }

    if (!$result['dkim']['found']) {
        $result['dkim']['status'] = 'not found (checked common selectors)';
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  IP Geolocation (Issue #18)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the ip-api.com request spec for getIpGeolocation() — shared with the
 * batched reputation runner (Issue #196 Step 2, runReputationModuleChecks())
 * so the URL/params can never drift between the serial and curl_multi paths.
 */
function geolocationRequest(string $ip): array {
    return ['url' => 'http://ip-api.com/json/' . urlencode($ip) . '?fields=status,country,countryCode,region,city,isp,org,as'];
}

/**
 * Parse an ip-api.com response body into getIpGeolocation()'s return shape.
 * IGNORES $httpCode — matches the legacy httpFetch()-based implementation,
 * which has no way to see the HTTP status code at all; only body
 * presence/shape gates the result. The batched path must replicate this
 * exactly (not tighten it) for byte-identical output.
 */
function parseGeolocationResponse(int $httpCode, ?string $body): ?array {
    if ($body === null) {
        return null;
    }

    $data = json_decode($body, true);
    if (!$data || $data['status'] !== 'success') {
        return null;
    }

    return [
        'country' => isset($data['country']) ? $data['country'] : '',
        'country_code' => isset($data['countryCode']) ? $data['countryCode'] : '',
        'region' => isset($data['region']) ? $data['region'] : '',
        'city' => isset($data['city']) ? $data['city'] : '',
        'isp' => isset($data['isp']) ? $data['isp'] : '',
        'org' => isset($data['org']) ? $data['org'] : '',
        'as' => isset($data['as']) ? $data['as'] : '',
    ];
}

/**
 * Get geolocation info for an IP address using ip-api.com (free, no key needed).
 * Rate limit: 45 requests/minute.
 */
function getIpGeolocation(string $ip): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $req = geolocationRequest($ip);
    $response = httpFetch($req['url'], ['timeout' => 3]);

    return parseGeolocationResponse(0, $response);
}


// ═══════════════════════════════════════════════════════════════════
//  SSL/TLS certificate info (Issue #19)
// ═══════════════════════════════════════════════════════════════════

/**
 * Fetch SSL certificate info for a domain.
 */
function getSslInfo(string $domain): ?array {
    // Issue #197: vet before connecting, then pin to the checked IP — connecting to
    // "ssl://{$domain}:443" directly would let the transport re-resolve $domain itself.
    $vet = resolveAndVetHost($domain);
    if ($vet === null) {
        return null;
    }

    $ctx = stream_context_create([
        'ssl' => [
            'capture_peer_cert' => true,
            'verify_peer' => false,
            'verify_peer_name' => false,
            'peer_name' => $domain, // keep SNI + hostname matching pinned to the real host
        ],
    ]);

    $client = @stream_socket_client(
        'ssl://' . bracketIp($vet['ip']) . ':443',
        $errno,
        $errstr,
        5,
        STREAM_CLIENT_CONNECT,
        $ctx
    );

    if (!$client) {
        return null;
    }

    $params = stream_context_get_params($client);
    fclose($client);

    if (!isset($params['options']['ssl']['peer_certificate'])) {
        return null;
    }

    $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
    if (!$cert) {
        return null;
    }

    $result = [
        'subject' => isset($cert['subject']['CN']) ? $cert['subject']['CN'] : '',
        'issuer' => isset($cert['issuer']['O']) ? $cert['issuer']['O'] : (isset($cert['issuer']['CN']) ? $cert['issuer']['CN'] : ''),
        'valid_from' => date('Y-m-d H:i:s', $cert['validFrom_time_t']),
        'valid_to' => date('Y-m-d H:i:s', $cert['validTo_time_t']),
        'serial' => isset($cert['serialNumberHex']) ? $cert['serialNumberHex'] : '',
    ];

    // Days until expiry
    $expiryTime = $cert['validTo_time_t'];
    $daysLeft = (int)ceil(($expiryTime - time()) / 86400);
    $result['expires_in'] = $daysLeft . ' days';
    $result['expired'] = ($daysLeft <= 0);

    // SAN (Subject Alternative Names)
    if (isset($cert['extensions']['subjectAltName'])) {
        $sans = array_map('trim', explode(',', $cert['extensions']['subjectAltName']));
        $result['san'] = array_map(function($s) {
            return str_replace('DNS:', '', $s);
        }, $sans);
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  WHOIS field parsing
// ═══════════════════════════════════════════════════════════════════

function parseWhoisFields(string $text): array {
    $fields = [];

    $single = [
        'Domain Name'        => '/Domain Name:\s*(.+)/i',
        'Registrar'          => '/Registrar:\s*(.+)/i',
        'Creation Date'      => '/Creat(?:ion|ed) Date:\s*(.+)/i',
        'Expiry Date'        => '/Expir(?:y|ation) Date:\s*(.+)/i',
        'Updated Date'       => '/Updated Date:\s*(.+)/i',
        'Registrant Org'     => '/Registrant Organi[sz]ation:\s*(.+)/i',
        'Registrant Country' => '/Registrant Country:\s*(.+)/i',
    ];

    foreach ($single as $label => $regex) {
        if (preg_match($regex, $text, $m)) {
            $fields[$label] = trim($m[1]);
        }
    }

    // Multi-value fields
    if (preg_match_all('/Domain Status:\s*(.+)/i', $text, $m)) {
        $fields['Status'] = array_map('trim', $m[1]);
    }

    if (preg_match_all('/Name Server:\s*(.+)/i', $text, $m)) {
        $fields['Name Servers'] = array_map('trim', $m[1]);
    }

    // Domain age (Issue #20)
    if (isset($fields['Creation Date'])) {
        $creationTime = strtotime($fields['Creation Date']);
        if ($creationTime) {
            $now = new DateTime();
            $created = new DateTime('@' . $creationTime);
            $diff = $created->diff($now);

            $ageParts = [];
            if ($diff->y > 0) {
                $ageParts[] = $diff->y . ' year' . ($diff->y !== 1 ? 's' : '');
            }
            if ($diff->m > 0) {
                $ageParts[] = $diff->m . ' month' . ($diff->m !== 1 ? 's' : '');
            }
            if (empty($ageParts) && $diff->d > 0) {
                $ageParts[] = $diff->d . ' day' . ($diff->d !== 1 ? 's' : '');
            }

            if (!empty($ageParts)) {
                $fields['Domain Age'] = implode(', ', $ageParts);
            }
        }
    }

    // Expiry countdown
    if (isset($fields['Expiry Date'])) {
        $expiryTime = strtotime($fields['Expiry Date']);
        if ($expiryTime) {
            $daysLeft = (int)ceil(($expiryTime - time()) / 86400);
            $fields['Expires In'] = $daysLeft . ' days';
        }
    }

    return $fields;
}


// ═══════════════════════════════════════════════════════════════════
//  RDAP lookup
// ═══════════════════════════════════════════════════════════════════

function rdapLookup(string $domain): ?array {
    $url = "https://rdap.org/domain/" . urlencode($domain);

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_HTTPHEADER     => ['Accept: application/rdap+json'],
            CURLOPT_USERAGENT      => 'mwWhoisLookup/1.0',
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
        ]);
        $response = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($response === false || $code >= 400) {
            return null;
        }
    } else {
        $ctx = stream_context_create([
            'http' => [
                'header' => "Accept: application/rdap+json\r\n",
                'timeout' => 5,
                'follow_location' => 1,
                'max_redirects' => 5,
                'ignore_errors' => true,
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $response = @file_get_contents($url, false, $ctx);

        if ($response === false) {
            return null;
        }
    }

    $data = json_decode($response, true);

    if (!$data) {
        return null;
    }

    if (isset($data['errorCode'])) {
        return null;
    }

    return $data;
}

function formatRdapResponse(array $rdap): string {
    $lines = [];

    if (isset($rdap['ldhName'])) {
        $lines[] = "Domain Name: " . strtoupper($rdap['ldhName']);
    }

    if (isset($rdap['status']) && is_array($rdap['status'])) {
        foreach ($rdap['status'] as $s) {
            $lines[] = "Domain Status: " . $s;
        }
    }

    // Map RDAP event actions to WHOIS-style field names so parseWhoisFields() can extract them
    $eventActionMap = [
        'registration'                  => 'Creation Date',
        'expiration'                    => 'Expiry Date',
        'last changed'                  => 'Updated Date',
        'last update of rdap database'  => 'RDAP Last Update',
        'transfer'                      => 'Transfer Date',
    ];

    if (isset($rdap['events']) && is_array($rdap['events'])) {
        foreach ($rdap['events'] as $e) {
            $action = isset($e['eventAction']) ? $e['eventAction'] : '';
            $date = isset($e['eventDate']) ? $e['eventDate'] : '';

            $label = isset($eventActionMap[strtolower($action)])
                ? $eventActionMap[strtolower($action)]
                : ucfirst($action);

            $lines[] = $label . ": " . $date;
        }
    }

    if (isset($rdap['entities']) && is_array($rdap['entities'])) {
        foreach ($rdap['entities'] as $entity) {
            $roles = '';
            if (isset($entity['roles'])) {
                $roles = implode(', ', $entity['roles']);
            }

            $handle = '';
            if (isset($entity['handle'])) {
                $handle = $entity['handle'];
            }

            if ($roles) {
                $lines[] = ucfirst($roles) . ": " . $handle;
            }

            if (isset($entity['vcardArray'][1]) && is_array($entity['vcardArray'][1])) {
                foreach ($entity['vcardArray'][1] as $vc) {
                    if ($vc[0] === 'fn') {
                        $lines[] = "  Name: " . $vc[3];
                    }
                    if ($vc[0] === 'org') {
                        if (is_array($vc[3])) {
                            $lines[] = "  Organization: " . $vc[3][0];
                        } else {
                            $lines[] = "  Organization: " . $vc[3];
                        }
                    }
                }
            }
        }
    }

    if (isset($rdap['nameservers']) && is_array($rdap['nameservers'])) {
        foreach ($rdap['nameservers'] as $ns) {
            $nsName = '';
            if (isset($ns['ldhName'])) {
                $nsName = $ns['ldhName'];
            }
            $lines[] = "Name Server: " . $nsName;
        }
    }

    return implode("\n", $lines);
}


// ═══════════════════════════════════════════════════════════════════
//  JSON response helper
// ═══════════════════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════════════════
//  Registrar reputation (Issue #51)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check if a registrar is flagged as problematic/spam-friendly.
 *
 * Returns null if unknown, or an associative array with reputation info.
 *
 * @param  string $registrar  The registrar name from WHOIS data
 * @return array|null          ['rating' => 'caution'|'warning', 'reason' => string]
 */
function checkRegistrarReputation(string $registrar): ?array {
    // Normalise for matching
    $lower = strtolower(trim($registrar));

    // Known problematic registrars (curated list)
    $flagged = [
        'todaynic.com'       => ['rating' => 'caution', 'reason' => 'Associated with high volumes of spam and abuse domains'],
        'regru-ru'           => ['rating' => 'caution', 'reason' => 'Frequently used for abuse domains in some reports'],
        'west263'            => ['rating' => 'caution', 'reason' => 'Associated with high abuse rates'],
        'bizcn.com'          => ['rating' => 'caution', 'reason' => 'Known for high abuse domain registration volumes'],
        'ename'              => ['rating' => 'caution', 'reason' => 'Elevated abuse domain rates reported'],
        'xinnet'             => ['rating' => 'caution', 'reason' => 'Elevated abuse domain rates reported'],
        'jiangsu bangning'   => ['rating' => 'caution', 'reason' => 'Elevated abuse domain rates reported'],
        'hichina'            => ['rating' => 'caution', 'reason' => 'Higher-than-average abuse rates reported'],
        'web commerce'       => ['rating' => 'caution', 'reason' => 'Associated with fraudulent domain registrations'],
        'nicenic'            => ['rating' => 'caution', 'reason' => 'Frequently used for phishing domains'],
    ];

    foreach ($flagged as $pattern => $info) {
        if (str_contains($lower, $pattern) ) {
            return $info;
        }
    }

    return null;
}

// ═══════════════════════════════════════════════════════════════════
//  Google Safe Browsing check (Issue #52)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the Safe Browsing request spec — shared with the batched reputation
 * runner (Issue #196 Step 2).
 */
function safeBrowsingRequest(string $domain, string $apiKey): array {
    $url = 'https://safebrowsing.googleapis.com/v4/threatMatches:find?key=' . urlencode($apiKey);
    $payload = json_encode([
        'client' => ['clientId' => 'mwwhois', 'clientVersion' => '1.0'],
        'threatInfo' => [
            'threatTypes' => ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
            'platformTypes' => ['ANY_PLATFORM'],
            'threatEntryTypes' => ['URL'],
            'threatEntries' => [
                ['url' => 'http://' . $domain . '/'],
                ['url' => 'https://' . $domain . '/'],
            ],
        ],
    ]);

    return ['url' => $url, 'post' => $payload, 'headers' => ['Content-Type: application/json']];
}

/**
 * Parse a Safe Browsing response into checkSafeBrowsing()'s return shape.
 */
function parseSafeBrowsingResponse(int $httpCode, ?string $body): array {
    if ($httpCode !== 200 || !$body) {
        return ['safe' => true, 'threats' => [], 'error' => 'API unavailable'];
    }

    $data = json_decode($body, true);
    if (!empty($data['matches'])) {
        $threats = array_map(function ($m) {
            return $m['threatType'];
        }, $data['matches']);
        return ['safe' => false, 'threats' => array_unique($threats)];
    }

    return ['safe' => true, 'threats' => []];
}

/**
 * Check a domain against the Google Safe Browsing API.
 *
 * @param  string $domain  The domain to check
 * @param  string $apiKey  Google Safe Browsing API key
 * @return array           ['safe' => bool, 'threats' => array]
 */
function checkSafeBrowsing(string $domain, string $apiKey): array {
    $req = safeBrowsingRequest($domain, $apiKey);

    $ch = curl_init($req['url']);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $req['post'],
        CURLOPT_HTTPHEADER => $req['headers'],
        CURLOPT_TIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return parseSafeBrowsingResponse($httpCode, $response === false ? null : $response);
}


// ═══════════════════════════════════════════════════════════════════
//  VirusTotal domain reputation (Issue #53)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the VirusTotal request spec — shared with the batched reputation
 * runner (Issue #196 Step 2).
 */
function virusTotalRequest(string $domain, string $apiKey): array {
    return [
        'url' => 'https://www.virustotal.com/api/v3/domains/' . urlencode($domain),
        'headers' => ['x-apikey: ' . $apiKey],
    ];
}

/**
 * Parse a VirusTotal response into checkVirusTotal()'s return shape.
 */
function parseVirusTotalResponse(int $httpCode, ?string $body): ?array {
    if ($httpCode !== 200 || !$body) {
        return null;
    }

    $data = json_decode($body, true);
    if (empty($data['data']['attributes']['last_analysis_stats'])) {
        return null;
    }

    $stats = $data['data']['attributes']['last_analysis_stats'];
    return [
        'malicious'   => $stats['malicious'] ?? 0,
        'suspicious'  => $stats['suspicious'] ?? 0,
        'harmless'    => $stats['harmless'] ?? 0,
        'undetected'  => $stats['undetected'] ?? 0,
        'reputation'  => $data['data']['attributes']['reputation'] ?? 0,
        'categories'  => $data['data']['attributes']['categories'] ?? [],
    ];
}

/**
 * Query VirusTotal for domain reputation.
 *
 * @param  string $domain  The domain to check
 * @param  string $apiKey  VirusTotal API key
 * @return array|null      Reputation info or null on failure
 */
function checkVirusTotal(string $domain, string $apiKey): ?array {
    $req = virusTotalRequest($domain, $apiKey);

    $ch = curl_init($req['url']);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => $req['headers'],
        CURLOPT_TIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return parseVirusTotalResponse($httpCode, $response === false ? null : $response);
}


function sendJson(array $data, int $status = 200): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    // Issue #193: flush the response to the client NOW — any register_shutdown_function
    // work queued by the caller (e.g. the deferred TLD/PSL refresh) then runs after the
    // client has already received its reply, instead of the client waiting on it.
    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    }
    exit;
}

function sendError(string $message, int $status = 400): void {
    sendJson(['error' => $message], $status);
}


// ═══════════════════════════════════════════════════════════════════
//  Subdomain discovery (Issue #46)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check common subdomains for a domain and return which ones resolve.
 *
 * Issue #196 Step 2: ~37 prefixes used to be resolved with ~37 SERIAL
 * gethostbyname() calls (worst case very slow — each one blocks on its own
 * DNS round-trip). When `dig` is available, resolve them all CONCURRENTLY
 * using the same background-subshell `.part`->`mv` pattern
 * checkDnsPropagation() already uses (Issue #194), capped at ~4s total.
 * Falls back to the original serial gethostbyname() loop when `dig` isn't
 * on the host. Output shape is IDENTICAL either way:
 * [['subdomain' => string, 'ip' => string], ...], in prefix-list order,
 * containing only the prefixes that actually resolved.
 *
 * @param  string    $domain        The base domain (e.g. example.com)
 * @param  bool|null $digAvailable  Override the `dig`-availability
 *                                   auto-detection (dependency injection for
 *                                   tests); null (default) auto-detects via
 *                                   `command -v dig`.
 * @return array                    Array of ['subdomain' => string, 'ip' => string]
 */
function discoverSubdomains(string $domain, ?bool $digAvailable = null): array {
    $prefixes = [
        'www', 'mail', 'ftp', 'smtp', 'pop', 'imap',
        'webmail', 'api', 'cdn', 'dev', 'staging', 'test',
        'admin', 'portal', 'blog', 'shop', 'store', 'app',
        'ns1', 'ns2', 'mx', 'vpn', 'remote', 'ssh',
        'git', 'ci', 'status', 'docs', 'help', 'support',
        'm', 'mobile', 'beta', 'alpha', 'demo', 'sandbox',
        'media', 'static', 'assets', 'img', 'images',
    ];

    if ($digAvailable === null) {
        static $hasDig = null;
        if ($hasDig === null) {
            $hasDig = (bool) @shell_exec('command -v dig 2>/dev/null');
        }
        $digAvailable = $hasDig;
    }

    return $digAvailable
        ? discoverSubdomainsViaDig($domain, $prefixes)
        : discoverSubdomainsSerial($domain, $prefixes);
}

/**
 * The ORIGINAL serial gethostbyname()-based implementation, kept intact as
 * the fallback for hosts without a `dig` binary (Issue #196 Step 2).
 */
function discoverSubdomainsSerial(string $domain, array $prefixes): array {
    $results = [];
    foreach ($prefixes as $prefix) {
        $fqdn = $prefix . '.' . $domain;
        $ip = @gethostbyname($fqdn);
        // gethostbyname returns the hostname unchanged if it doesn't resolve
        if ($ip !== $fqdn) {
            $results[] = [
                'subdomain' => $fqdn,
                'ip' => $ip,
            ];
        }
    }

    return $results;
}

/**
 * Parse one FQDN's raw `dig +short A` output into the discoverSubdomains()
 * entry shape, or null if it didn't resolve. Pure — no I/O — so the exact
 * same parsing discoverSubdomainsViaDig() applies after polling temp files
 * can be unit-tested directly against synthetic dig output. Only the first
 * line that is itself a literal IPv4 address is used — `dig +short A` can
 * also emit intermediate CNAME lines for an aliased name, which this skips,
 * matching gethostbyname()'s A-record-only, CNAME-transparent contract.
 */
function parseDigSubdomainOutput(string $fqdn, ?string $output): ?array {
    if ($output === null || trim($output) === '') {
        return null;
    }

    $lines = array_filter(array_map('trim', explode("\n", trim($output))));
    foreach ($lines as $line) {
        if (filter_var($line, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return ['subdomain' => $fqdn, 'ip' => $line];
        }
    }

    return null;
}

/**
 * Parallel `dig`-based subdomain discovery — fires one background `dig`
 * subshell per prefix (the same `.part`->`mv` pattern checkDnsPropagation()
 * uses, Issue #194) instead of resolving them one at a time, then polls for
 * the results with a ~4s hard cap (0.5s initial sleep + up to 3.5s of 100ms
 * polls — identical budget to checkDnsPropagation()'s).
 */
function discoverSubdomainsViaDig(string $domain, array $prefixes): array {
    $tmpDir = sys_get_temp_dir();
    $pid = getmypid();
    $jobs = [];

    foreach ($prefixes as $i => $prefix) {
        $fqdn = $prefix . '.' . $domain;
        $tmpFile = $tmpDir . DIRECTORY_SEPARATOR . 'subdomain_' . $pid . '_' . $i;
        $jobs[$i] = ['fqdn' => $fqdn, 'file' => $tmpFile];
        // See checkDnsPropagation()'s comment on why this MUST be a
        // parenthesised subshell (so the whole `dig ...; mv ...` sequence
        // backgrounds together) writing to a `.part` file that's only
        // renamed into place once `dig` has actually finished — a bare
        // `dig ... > $tmpFile &` would create $tmpFile the instant the shell
        // forks, before dig has produced any output.
        $cmd = '( dig +short +time=2 +tries=1 A ' . escapeshellarg($fqdn) . ' > '
             . escapeshellarg($tmpFile . '.part') . ' 2>/dev/null; mv '
             . escapeshellarg($tmpFile . '.part') . ' ' . escapeshellarg($tmpFile) . ' ) &';
        @exec($cmd);
    }

    // Wait for all background processes (max ~4s total, mirrors checkDnsPropagation()).
    usleep(500000);
    $waited = 0;
    while ($waited < 35) {
        $allDone = true;
        foreach ($jobs as $job) {
            if (!file_exists($job['file'])) {
                $allDone = false;
                break;
            }
        }
        if ($allDone) break;
        usleep(100000);
        $waited++;
    }

    $results = [];
    foreach ($jobs as $job) {
        $output = @file_get_contents($job['file']);
        @unlink($job['file']);
        @unlink($job['file'] . '.part'); // in case dig never finished within the time cap
        $entry = parseDigSubdomainOutput($job['fqdn'], $output === false ? null : $output);
        if ($entry !== null) {
            $results[] = $entry;
        }
    }

    return $results;
}


// ═══════════════════════════════════════════════════════════════════
//  Have I Been Pwned — domain breach search (Issue #65)
// ═══════════════════════════════════════════════════════════════════

/**
 * Check a domain for known data breaches via HIBP API.
 *
 * @param  string $domain  The domain to check
 * @param  string $apiKey  HIBP API key
 * @return array|null      Array of breach info or null on failure
 */
function checkHibpDomain(string $domain, string $apiKey): ?array {
    $url = 'https://haveibeenpwned.com/api/v3/breaches?domain=' . urlencode($domain);

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER => [
            'hibp-api-key: ' . $apiKey,
            'User-Agent: mwWhoIs-DomainLookup',
        ],
        CURLOPT_TIMEOUT => 5,
    ]);
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode === 404) {
        return []; // No breaches found
    }

    if ($httpCode !== 200 || !$response) {
        return null; // API error
    }

    $breaches = json_decode($response, true);
    if (!is_array($breaches)) {
        return null;
    }

    return array_map(function ($b) {
        return [
            'name'        => $b['Name'] ?? '',
            'title'       => $b['Title'] ?? '',
            'date'        => $b['BreachDate'] ?? '',
            'pwn_count'   => $b['PwnCount'] ?? 0,
            'data_classes' => $b['DataClasses'] ?? [],
        ];
    }, $breaches);
}


// ═══════════════════════════════════════════════════════════════════
//  DNSSEC validation check (Issue #93)
// ═══════════════════════════════════════════════════════════════════

function checkDnssec(string $domain): array {
    $result = ['signed' => false, 'ds_records' => 0, 'status' => 'unsigned'];

    // Check for DS records (Delegation Signer) which indicate DNSSEC
    $ds = @dns_get_record($domain, DNS_ANY);
    if ($ds) {
        foreach ($ds as $rec) {
            if (isset($rec['type']) && strtoupper($rec['type']) === 'DS') {
                $result['signed'] = true;
                $result['ds_records']++;
            }
        }
    }

    // Also check the same DNS_ANY result for a DNSKEY record (Issue #191 — this used to
    // issue an identical, second dns_get_record($domain, DNS_ANY) query; $ds already has it)
    if (!$result['signed'] && $ds) {
        foreach ($ds as $rec) {
            if (isset($rec['type']) && strtoupper($rec['type']) === 'DNSKEY') {
                $result['signed'] = true;
                break;
            }
        }
    }

    // Fallback: use dig if available
    if (!$result['signed']) {
        $digOutput = @shell_exec('dig +short +time=2 +tries=1 DS ' . escapeshellarg($domain) . ' 2>/dev/null');
        if ($digOutput && trim($digOutput)) {
            $result['signed'] = true;
            $result['ds_records'] = count(array_filter(explode("\n", trim($digOutput))));
        }
    }

    $result['status'] = $result['signed'] ? 'signed' : 'unsigned';
    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Certificate Transparency log lookup (Issue #94)
// ═══════════════════════════════════════════════════════════════════

function checkCertTransparency(string $domain): ?array {
    $url = 'https://crt.sh/?q=' . urlencode($domain) . '&output=json&deduplicate=Y';

    $response = httpFetch($url, ['timeout' => 5, 'maxbytes' => 2097152]);
    if (!$response) {
        return null;
    }

    $certs = json_decode($response, true);
    if (!is_array($certs)) {
        return null;
    }

    // Get the 10 most recent
    usort($certs, function ($a, $b) {
        return strtotime($b['entry_timestamp'] ?? '0') - strtotime($a['entry_timestamp'] ?? '0');
    });

    $recent = array_slice($certs, 0, 10);
    return [
        'total' => count($certs),
        'recent' => array_map(function ($c) {
            return [
                'issuer'    => $c['issuer_name'] ?? '',
                'not_before' => $c['not_before'] ?? '',
                'not_after'  => $c['not_after'] ?? '',
                'common_name' => $c['common_name'] ?? '',
            ];
        }, $recent),
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  Domain age risk scoring (Issue #95)
// ═══════════════════════════════════════════════════════════════════

function assessDomainAgeRisk(array $parsed): ?array {
    if (empty($parsed['Creation Date'])) {
        return null;
    }

    try {
        $created = new DateTime($parsed['Creation Date']);
        $now = new DateTime();
        $diff = $now->diff($created);
        $days = (int)$diff->format('%a');

        $risk = 'low';
        $reason = 'Domain is well established';
        if ($days < 30) {
            $risk = 'high';
            $reason = 'Domain registered less than 30 days ago — newly registered domains are frequently used for phishing and spam';
        } elseif ($days < 90) {
            $risk = 'medium';
            $reason = 'Domain registered less than 90 days ago';
        } elseif ($days < 365) {
            $risk = 'low-medium';
            $reason = 'Domain is less than 1 year old';
        }

        return ['risk' => $risk, 'days_old' => $days, 'reason' => $reason];
    } catch (Exception $e) {
        return null;
    }
}


// ═══════════════════════════════════════════════════════════════════
//  AbuseIPDB integration (Issue #96)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the AbuseIPDB request spec — shared with the batched reputation
 * runner (Issue #196 Step 2).
 */
function abuseIpdbRequest(string $ip, string $apiKey): array {
    return [
        'url' => 'https://api.abuseipdb.com/api/v2/check?' . http_build_query(['ipAddress' => $ip, 'maxAgeInDays' => 90]),
        'headers' => ['Key: ' . $apiKey, 'Accept: application/json'],
    ];
}

/**
 * Parse an AbuseIPDB response into checkAbuseIPDB()'s return shape.
 */
function parseAbuseIpdbResponse(int $httpCode, ?string $body): ?array {
    if ($httpCode !== 200 || !$body) {
        return null;
    }

    $data = json_decode($body, true);
    if (!isset($data['data'])) {
        return null;
    }

    $d = $data['data'];
    return [
        'abuse_score'    => $d['abuseConfidenceScore'] ?? 0,
        'total_reports'  => $d['totalReports'] ?? 0,
        'country_code'   => $d['countryCode'] ?? '',
        'isp'            => $d['isp'] ?? '',
        'is_tor'         => $d['isTor'] ?? false,
        'last_reported'  => $d['lastReportedAt'] ?? null,
    ];
}

function checkAbuseIPDB(string $ip, string $apiKey): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $req = abuseIpdbRequest($ip, $apiKey);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $req['url'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_HTTPHEADER => $req['headers'],
    ]);
    $response = curl_exec($ch);
    $httpCode = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    return parseAbuseIpdbResponse($httpCode, $response === false ? null : $response);
}


// ═══════════════════════════════════════════════════════════════════
//  Shodan integration (Issue #97)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the Shodan request spec — shared with the batched reputation runner
 * (Issue #196 Step 2).
 */
function shodanRequest(string $ip, string $apiKey): array {
    return ['url' => 'https://api.shodan.io/shodan/host/' . urlencode($ip) . '?key=' . urlencode($apiKey) . '&minify=true'];
}

/**
 * Parse a Shodan response into checkShodan()'s return shape. IGNORES
 * $httpCode — matches the legacy httpFetch()-based implementation, which has
 * no way to see the HTTP status; only body presence/shape (including the
 * body-level "error" key) gates the result.
 */
function parseShodanResponse(int $httpCode, ?string $body): ?array {
    if (!$body) {
        return null;
    }

    $data = json_decode($body, true);
    if (!is_array($data) || isset($data['error'])) {
        return null;
    }

    $ports = $data['ports'] ?? [];
    sort($ports);

    return [
        'ports'       => $ports,
        'os'          => $data['os'] ?? null,
        'org'         => $data['org'] ?? '',
        'vulns'       => array_keys($data['vulns'] ?? []),
        'last_update' => $data['last_update'] ?? '',
    ];
}

function checkShodan(string $ip, string $apiKey): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return null;
    }

    $req = shodanRequest($ip, $apiKey);
    $response = httpFetch($req['url'], ['timeout' => 5]);

    return parseShodanResponse(0, $response);
}


// ═══════════════════════════════════════════════════════════════════
//  PhishTank integration (Issue #98)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the PhishTank request spec — shared with the batched reputation
 * runner (Issue #196 Step 2).
 */
function phishTankRequest(string $domain, string $apiKey): array {
    $postData = http_build_query([
        'url' => 'https://' . $domain,
        'format' => 'json',
        'app_key' => $apiKey,
    ]);

    return [
        'url' => 'https://checkurl.phishtank.com/checkurl/',
        'post' => $postData,
        'headers' => ['Content-Type: application/x-www-form-urlencoded'],
    ];
}

/**
 * Parse a PhishTank response into checkPhishTank()'s return shape. IGNORES
 * $httpCode — matches the legacy httpFetch()-based implementation.
 */
function parsePhishTankResponse(int $httpCode, ?string $body): ?array {
    if (!$body) {
        return null;
    }

    $data = json_decode($body, true);
    if (!isset($data['results'])) {
        return null;
    }

    return [
        'in_database' => (bool)($data['results']['in_database'] ?? false),
        'is_phish'    => (bool)($data['results']['valid'] ?? false),
        'verified'    => (bool)($data['results']['verified'] ?? false),
        'phish_id'    => $data['results']['phish_id'] ?? null,
    ];
}

function checkPhishTank(string $domain, string $apiKey): ?array {
    $req = phishTankRequest($domain, $apiKey);

    $response = httpFetch($req['url'], [
        'timeout' => 5,
        'post'    => $req['post'],
        'headers' => $req['headers'],
    ]);

    return parsePhishTankResponse(0, $response);
}


// ═══════════════════════════════════════════════════════════════════
//  URLhaus malware check (Issue #99)
// ═══════════════════════════════════════════════════════════════════

/**
 * Build the URLhaus request spec — shared with the batched reputation runner
 * (Issue #196 Step 2).
 */
function urlhausRequest(string $domain): array {
    return [
        'url' => 'https://urlhaus-api.abuse.ch/v1/host/',
        'post' => http_build_query(['host' => $domain]),
        'headers' => ['Content-Type: application/x-www-form-urlencoded'],
    ];
}

/**
 * Parse a URLhaus response into checkUrlhaus()'s return shape. IGNORES
 * $httpCode — matches the legacy httpFetch()-based implementation.
 */
function parseUrlhausResponse(int $httpCode, ?string $body): ?array {
    if (!$body) {
        return null;
    }

    $data = json_decode($body, true);
    if (!is_array($data)) {
        return null;
    }

    return [
        'status'       => $data['query_status'] ?? 'unknown',
        'urls_total'   => (int)($data['urls_online'] ?? 0),
        'blacklists'   => $data['blacklists'] ?? [],
        'tags'         => array_slice($data['tags'] ?? [], 0, 10),
    ];
}

function checkUrlhaus(string $domain): ?array {
    $req = urlhausRequest($domain);

    $response = httpFetch($req['url'], [
        'timeout' => 5,
        'post'    => $req['post'],
        'headers' => $req['headers'],
    ]);

    return parseUrlhausResponse(0, $response);
}


// ═══════════════════════════════════════════════════════════════════
//  Spamhaus blocklist check (Issue #100)
// ═══════════════════════════════════════════════════════════════════

function checkSpamhaus(string $ip): ?array {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return null;
    }

    // Reverse IP for DNSBL query
    $reversed = implode('.', array_reverse(explode('.', $ip)));
    $zones = [
        'zen.spamhaus.org' => 'Spamhaus ZEN (combined)',
        'sbl.spamhaus.org' => 'SBL (Spam)',
        'xbl.spamhaus.org' => 'XBL (Exploits)',
        'pbl.spamhaus.org' => 'PBL (Policy)',
    ];

    $listed = [];
    foreach ($zones as $zone => $label) {
        $lookup = $reversed . '.' . $zone;
        $result = @dns_get_record($lookup, DNS_A);
        if ($result && count($result) > 0) {
            $listed[] = ['zone' => $zone, 'label' => $label, 'response' => $result[0]['ip'] ?? ''];
        }
    }

    return [
        'listed' => count($listed) > 0,
        'lists'  => $listed,
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  MTA-STS check (Issue #101)
// ═══════════════════════════════════════════════════════════════════

function checkMtaSts(string $domain): array {
    $result = ['found' => false, 'record' => null, 'mode' => null];

    // Check _mta-sts TXT record
    $records = @dns_get_record('_mta-sts.' . $domain, DNS_TXT);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=STSv1') !== false) {
                $result['found'] = true;
                $result['record'] = $rec['txt'];

                if (stripos($rec['txt'], 'enforce') !== false) {
                    $result['mode'] = 'enforce';
                } elseif (stripos($rec['txt'], 'testing') !== false) {
                    $result['mode'] = 'testing';
                } elseif (stripos($rec['txt'], 'none') !== false) {
                    $result['mode'] = 'none';
                }
                break;
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  BIMI record check (Issue #102)
// ═══════════════════════════════════════════════════════════════════

function checkBimi(string $domain): array {
    $result = ['found' => false, 'record' => null, 'logo_url' => null];

    $records = @dns_get_record('default._bimi.' . $domain, DNS_TXT);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['txt']) && stripos($rec['txt'], 'v=BIMI1') !== false) {
                $result['found'] = true;
                $result['record'] = $rec['txt'];

                // Extract logo URL
                if (preg_match('/l=([^;\s]+)/i', $rec['txt'], $m)) {
                    $result['logo_url'] = trim($m[1]);
                }
                break;
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  DANE/TLSA record check (Issue #103)
// ═══════════════════════════════════════════════════════════════════

function checkDaneTlsa(string $domain): array {
    $result = ['found' => false, 'records' => []];

    // Check _443._tcp.{domain} for TLSA records
    $host = '_443._tcp.' . $domain;

    // PHP dns_get_record doesn't support TLSA natively, use dig
    $output = @shell_exec('dig +short +time=2 +tries=1 TLSA ' . escapeshellarg($host) . ' 2>/dev/null');
    if ($output && trim($output)) {
        $lines = array_filter(explode("\n", trim($output)));
        $result['found'] = true;
        foreach ($lines as $line) {
            $parts = preg_split('/\s+/', trim($line), 4);
            if (count($parts) >= 4) {
                $result['records'][] = [
                    'usage'    => (int)$parts[0],
                    'selector' => (int)$parts[1],
                    'matching' => (int)$parts[2],
                    'data'     => substr($parts[3], 0, 32) . '...',
                ];
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  WHOIS privacy detection (Issue #104)
// ═══════════════════════════════════════════════════════════════════

function detectWhoisPrivacy(string $whoisText, array $parsed): array {
    $result = ['privacy_enabled' => false, 'indicators' => []];

    $privacyKeywords = [
        'REDACTED FOR PRIVACY',
        'Privacy Protection',
        'WhoisGuard',
        'Domains By Proxy',
        'Contact Privacy',
        'WHOIS PRIVACY',
        'Identity Protection',
        'Privacy Service',
        'Data Protected',
        'Withheld for Privacy',
        'Statutory Masking',
        'GDPR Redacted',
        'Not Disclosed',
        'Registration Private',
    ];

    foreach ($privacyKeywords as $keyword) {
        if (stripos($whoisText, $keyword) !== false) {
            $result['privacy_enabled'] = true;
            $result['indicators'][] = $keyword;
        }
    }

    // Check if registrant org looks like a privacy service
    $org = $parsed['Registrant Org'] ?? ($parsed['Organisation'] ?? '');
    $privacyOrgs = ['proxy', 'privacy', 'protect', 'guard', 'redacted', 'withheld'];
    foreach ($privacyOrgs as $term) {
        if ($org && stripos($org, $term) !== false) {
            $result['privacy_enabled'] = true;
            if (!in_array($org, $result['indicators'])) {
                $result['indicators'][] = 'Registrant: ' . $org;
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Hosting country risk assessment (Issue #105)
// ═══════════════════════════════════════════════════════════════════

function assessHostingRisk(?array $geolocation): ?array {
    if (!$geolocation || empty($geolocation['country_code'])) {
        return null;
    }

    // Countries frequently flagged in threat intelligence reports
    $highRisk = ['RU', 'CN', 'KP', 'IR', 'SY', 'CU'];
    $mediumRisk = ['UA', 'RO', 'BG', 'NG', 'PK', 'BD', 'VN', 'BY'];

    $cc = strtoupper($geolocation['country_code']);
    $country = $geolocation['country'] ?? $cc;

    if (in_array($cc, $highRisk)) {
        return ['risk' => 'high', 'country' => $country, 'country_code' => $cc, 'reason' => 'Hosted in a jurisdiction frequently associated with cyber threats'];
    }
    if (in_array($cc, $mediumRisk)) {
        return ['risk' => 'medium', 'country' => $country, 'country_code' => $cc, 'reason' => 'Hosted in a jurisdiction with elevated cyber threat activity'];
    }

    return ['risk' => 'low', 'country' => $country, 'country_code' => $cc, 'reason' => ''];
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP Security Headers audit (Issue #106)
// ═══════════════════════════════════════════════════════════════════

function auditHttpHeaders(string $domain): ?array {
    // Issue #197: get_headers()'s stream-context wrapper re-resolves the hostname
    // itself and offers no way to pin a connection, so this now goes through curl
    // with resolveAndVetHost() + CURLOPT_RESOLVE. Redirects (this used to auto-follow
    // up to 3 hops) are followed manually so each hop's host gets re-vetted before
    // it's connected to — see fetchViaVettedCurl().
    $curlOpts = [
        CURLOPT_NOBODY         => true,
        CURLOPT_TIMEOUT        => 5,
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT      => 'mwWhoIs Security Audit',
    ];
    $fetch = fetchViaVettedCurl('https://' . $domain, $curlOpts);
    if ($fetch === null) {
        // Try HTTP fallback (matches the original's https-then-http behaviour)
        $fetch = fetchViaVettedCurl('http://' . $domain, $curlOpts);
        if ($fetch === null) {
            return null;
        }
    }

    // Normalise header keys to lowercase
    $h = [];
    foreach (preg_split('/\r\n|\n/', trim($fetch['headers'])) as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) === 2) {
            $h[strtolower(trim($parts[0]))] = trim($parts[1]);
        }
    }

    $checks = [
        'strict-transport-security' => ['label' => 'HSTS', 'desc' => 'Enforces HTTPS connections'],
        'content-security-policy'   => ['label' => 'CSP', 'desc' => 'Controls resource loading sources'],
        'x-frame-options'           => ['label' => 'X-Frame-Options', 'desc' => 'Prevents clickjacking'],
        'x-content-type-options'    => ['label' => 'X-Content-Type-Options', 'desc' => 'Prevents MIME sniffing'],
        'referrer-policy'           => ['label' => 'Referrer-Policy', 'desc' => 'Controls referrer information'],
        'permissions-policy'        => ['label' => 'Permissions-Policy', 'desc' => 'Controls browser features'],
        'cross-origin-opener-policy' => ['label' => 'COOP', 'desc' => 'Cross-origin opener policy'],
        'cross-origin-resource-policy' => ['label' => 'CORP', 'desc' => 'Cross-origin resource policy'],
    ];

    $results = [];
    $pass = 0;
    $total = count($checks);
    foreach ($checks as $header => $meta) {
        $present = isset($h[$header]);
        $value = $present ? $h[$header] : null;
        $results[] = ['header' => $meta['label'], 'description' => $meta['desc'], 'present' => $present, 'value' => $value];
        if ($present) {
            $pass++;
        }
    }

    $grade = 'F';
    $pct = ($pass / $total) * 100;
    if ($pct >= 87) {
        $grade = 'A';
    } elseif ($pct >= 75) {
        $grade = 'B';
    } elseif ($pct >= 62) {
        $grade = 'C';
    } elseif ($pct >= 50) {
        $grade = 'D';
    } elseif ($pct >= 37) {
        $grade = 'E';
    }

    return ['grade' => $grade, 'pass' => $pass, 'total' => $total, 'headers' => $results];
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP Redirect chain detection (Issue #107)
// ═══════════════════════════════════════════════════════════════════

function detectRedirectChain(string $domain): ?array {
    $chain = [];
    $url = 'http://' . $domain;
    $maxRedirects = 5; // Issue #192: was 10 — cap total hops
    $stillRedirecting = true;

    for ($i = 0; $i < $maxRedirects; $i++) {
        // Issue #197: this manually walks the redirect chain itself (FOLLOWLOCATION is
        // already off), which is exactly what makes it SSRF-prone — each Location header
        // is attacker-influenceable once the FIRST hop is. Re-vet every hop's host before
        // connecting to it, and stop (marking the hop as blocked) instead of following one
        // that resolves to a private/internal address.
        $hopHost = parse_url($url, PHP_URL_HOST);
        $hopPort = parse_url($url, PHP_URL_PORT);
        // Security: CURLOPT_RESOLVE pins below are host:PORT-scoped (443/80 only) — a
        // redirect naming any other port would make curl fall back to a LIVE DNS lookup
        // for that host:port, bypassing the pin entirely. Treat that the same as a
        // vetting failure rather than connect.
        $portOk = ($hopPort === null || in_array((int) $hopPort, [80, 443], true));
        $vet = ($hopHost && $portOk) ? resolveAndVetHost($hopHost) : null;
        if ($vet === null) {
            $chain[] = ['url' => $url, 'status' => null, 'blocked' => true];
            $stillRedirecting = false;
            break;
        }

        $ch = curl_init($url);
        $curlOpts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 3, // Issue #192: was 5 — per-hop TOTAL time cap
            CURLOPT_HEADER => true,
            CURLOPT_NOBODY => true,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT => 'mwWhoIs',
            CURLOPT_RESOLVE => [$hopHost . ':443:' . bracketIp($vet['ip']), $hopHost . ':80:' . bracketIp($vet['ip'])],
        ];
        if (defined('CURLOPT_PROTOCOLS')) { $curlOpts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) { $curlOpts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
        curl_setopt_array($ch, $curlOpts);
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $redirectUrl = curl_getinfo($ch, CURLINFO_REDIRECT_URL);
        curl_close($ch);

        $chain[] = ['url' => $url, 'status' => $httpCode];

        if ($httpCode >= 300 && $httpCode < 400 && $redirectUrl) {
            $url = $redirectUrl;
        } else {
            $stillRedirecting = false;
            break;
        }
    }

    // Suspicious = still redirecting when we hit our own hop cap (was "count($chain) > 5"
    // against a maxRedirects of 10; with the cap now equal to 5 that bare count comparison
    // could never fire, and would also false-flag a chain that resolves cleanly on hop 5).
    // Issue #197: a chain that redirects to a private/internal address is inherently
    // suspicious too — flag it rather than just quietly truncating.
    $wasBlocked = !empty(end($chain)['blocked']);
    $suspicious = ($stillRedirecting && count($chain) >= $maxRedirects) || $wasBlocked;
    $httpToHttps = false;
    if (count($chain) >= 2 && str_starts_with($chain[0]['url'], 'http://') && str_starts_with(end($chain)['url'], 'https://')) {
        $httpToHttps = true;
    }

    return ['chain' => $chain, 'hops' => count($chain), 'http_to_https' => $httpToHttps, 'suspicious' => $suspicious];
}


// ═══════════════════════════════════════════════════════════════════
//  TLS version & cipher suite audit (Issue #108)
// ═══════════════════════════════════════════════════════════════════

function auditTlsVersions(string $domain): ?array {
    // Issue #197: vet before connecting; pin every curl call AND the openssl s_client
    // fallback below to the checked IP (openssl s_client does its own DNS resolution
    // and would otherwise completely bypass the gate).
    $vet = resolveAndVetHost($domain);
    if ($vet === null) {
        return null;
    }
    $ip = $vet['ip'];
    $resolvePin = [$domain . ':443:' . bracketIp($ip)];

    $result = ['versions' => [], 'cipher' => null, 'protocol' => null, 'insecure' => false];

    // Check negotiated TLS version
    $ch = curl_init('https://' . $domain);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 5, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_RESOLVE => $resolvePin]);
    curl_exec($ch);
    $sslVersion = curl_getinfo($ch, CURLINFO_SSL_VERIFYRESULT);
    $protocol = curl_getinfo($ch, CURLINFO_PROTOCOL);

    // Get TLS version from verbose info
    $tlsVer = null;
    if (defined('CURLINFO_TLS_SSL_PTR')) {
        // Not available in all PHP versions
    }

    // Fallback: use openssl s_client — connect to the vetted IP directly (never the
    // hostname, which openssl would resolve itself), pass -servername for correct SNI.
    $output = @shell_exec(
        'echo | timeout 5 openssl s_client -connect ' . escapeshellarg(bracketIp($ip) . ':443')
        . ' -servername ' . escapeshellarg($domain) . ' 2>/dev/null | grep "Protocol\|Cipher"'
    );
    if ($output) {
        if (preg_match('/Protocol\s*:\s*(.+)/i', $output, $m)) {
            $result['protocol'] = trim($m[1]);
        }
        if (preg_match('/Cipher\s*:\s*(.+)/i', $output, $m)) {
            $result['cipher'] = trim($m[1]);
        }
    }
    curl_close($ch);

    // Test specific TLS versions
    $tests = [
        'TLSv1.0' => CURL_SSLVERSION_TLSv1_0,
        'TLSv1.1' => CURL_SSLVERSION_TLSv1_1,
        'TLSv1.2' => CURL_SSLVERSION_TLSv1_2,
    ];
    if (defined('CURL_SSLVERSION_TLSv1_3')) {
        $tests['TLSv1.3'] = CURL_SSLVERSION_TLSv1_3;
    }

    foreach ($tests as $name => $const) {
        $ch = curl_init('https://' . $domain);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_NOBODY => true, CURLOPT_TIMEOUT => 3, CURLOPT_SSL_VERIFYPEER => false, CURLOPT_SSLVERSION => $const, CURLOPT_RESOLVE => $resolvePin]);
        $ok = curl_exec($ch);
        $err = curl_errno($ch);
        curl_close($ch);
        $supported = ($err === 0);
        $result['versions'][$name] = $supported;
        if ($supported && ($name === 'TLSv1.0' || $name === 'TLSv1.1')) {
            $result['insecure'] = true;
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  CAA record check (Issue #109)
// ═══════════════════════════════════════════════════════════════════

function checkCaaRecords(string $domain): array {
    $result = ['found' => false, 'records' => []];

    // PHP dns_get_record supports CAA natively (PHP 8.4+)
    $records = @dns_get_record($domain, DNS_CAA);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['type']) && $rec['type'] === 'CAA') {
                $result['found'] = true;
                $result['records'][] = [
                    'flag'  => $rec['flags'] ?? 0,
                    'tag'   => $rec['tag'] ?? '',
                    'value' => $rec['value'] ?? '',
                ];
            }
        }
    }

    // Fallback via dig
    if (!$result['found']) {
        $output = @shell_exec('dig +short +time=2 +tries=1 CAA ' . escapeshellarg($domain) . ' 2>/dev/null');
        if ($output && trim($output)) {
            $lines = array_filter(explode("\n", trim($output)));
            foreach ($lines as $line) {
                $parts = preg_split('/\s+/', trim($line), 3);
                if (count($parts) >= 3) {
                    $result['found'] = true;
                    $result['records'][] = ['flag' => (int)$parts[0], 'tag' => $parts[1], 'value' => trim($parts[2], '"')];
                }
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Outbound SMTP (port 25) egress probe (Issue #195)
// ═══════════════════════════════════════════════════════════════════

/**
 * Detect whether outbound port 25 is reachable at all from this host. Shared
 * hosting commonly DROPs outbound port 25 at the firewall, which makes every
 * fsockopen($mx, 25) in checkSmtpSecurity() below take a flat ~5s (its connect
 * timeout) for no result. Probe a known-good public MX once a day and cache the
 * boolean so every lookup after the first doesn't pay that cost again.
 */
function isSmtpEgressOpen(): bool {
    $cacheKey = 'smtp_egress_open';
    $cached = getCached($cacheKey, 86400);
    if ($cached !== null) {
        return $cached === '1';
    }

    $fp = @fsockopen('gmail-smtp-in.l.google.com', 25, $errno, $errstr, 3);
    $open = (bool) $fp;
    if ($fp) {
        fclose($fp);
    }

    setCache($cacheKey, $open ? '1' : '0', 86400);
    return $open;
}


// ═══════════════════════════════════════════════════════════════════
//  SMTP banner & STARTTLS check (Issue #110)
// ═══════════════════════════════════════════════════════════════════

function checkSmtpSecurity(string $domain): ?array {
    // Get MX records
    $mxRecords = @dns_get_record($domain, DNS_MX);
    if (!$mxRecords || count($mxRecords) === 0) {
        return null;
    }

    // Sort by priority and use the first
    usort($mxRecords, function ($a, $b) {
        return ($a['pri'] ?? 99) - ($b['pri'] ?? 99);
    });
    $mxHost = $mxRecords[0]['target'] ?? null;
    if (!$mxHost) {
        return null;
    }

    $result = ['mx_host' => $mxHost, 'banner' => null, 'starttls' => false, 'reachable' => false];

    // Issue #195: skip the doomed flat-~5s connect attempt entirely when outbound
    // port 25 is known to be blocked.
    if (!isSmtpEgressOpen()) {
        $result['reachable'] = null;
        $result['blocked_egress'] = true;
        return $result;
    }

    // Issue #197: the domain's own MX target is attacker-controlled (a malicious domain
    // can publish an MX record pointing at internal infrastructure) — vet it and connect
    // to the checked IP, never the hostname itself.
    $mxVet = resolveAndVetHost($mxHost);
    if ($mxVet === null) {
        $result['ssrf_blocked'] = true;
        return $result;
    }

    $fp = @fsockopen(bracketIp($mxVet['ip']), 25, $errno, $errstr, 5);
    if (!$fp) {
        return $result;
    }

    $result['reachable'] = true;
    stream_set_timeout($fp, 5);

    // Read banner
    $banner = fgets($fp, 1024);
    $result['banner'] = trim($banner);

    // Send EHLO
    fwrite($fp, "EHLO mwwhois.check\r\n");
    $ehloResponse = '';
    while ($line = fgets($fp, 1024)) {
        $ehloResponse .= $line;
        if (preg_match('/^\d{3} /', $line)) {
            break;
        }
    }

    $result['starttls'] = (stripos($ehloResponse, 'STARTTLS') !== false);

    fwrite($fp, "QUIT\r\n");
    fclose($fp);

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Reverse IP lookup (Issue #111)
// ═══════════════════════════════════════════════════════════════════

function reverseIpLookup(string $ip): ?array {
    $url = 'https://api.hackertarget.com/reverseiplookup/?q=' . urlencode($ip);
    $response = httpFetch($url, ['timeout' => 5]);
    if (!$response || str_contains($response, 'error')  || str_contains($response, 'API count') ) {
        return null;
    }

    $domains = array_filter(array_map('trim', explode("\n", trim($response))));
    return ['ip' => $ip, 'count' => count($domains), 'domains' => array_slice($domains, 0, 25)];
}


// ═══════════════════════════════════════════════════════════════════
//  HTTP/2 and HTTP/3 support detection (Issue #112)
// ═══════════════════════════════════════════════════════════════════

function checkHttpVersions(string $domain): array {
    $result = ['http2' => false, 'http3' => false, 'protocol' => null];

    // Issue #197: vet before connecting; return the same default/failure shape without
    // connecting if the host doesn't resolve to a public address.
    $vet = resolveAndVetHost($domain);
    if ($vet === null) {
        return $result;
    }

    $ch = curl_init('https://' . $domain);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_TIMEOUT => 5,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_2_0,
        CURLOPT_HEADER => true,
        CURLOPT_RESOLVE => [$domain . ':443:' . bracketIp($vet['ip']), $domain . ':80:' . bracketIp($vet['ip'])],
    ]);
    $response = curl_exec($ch);
    $httpVersion = curl_getinfo($ch, CURLINFO_HTTP_VERSION);
    curl_close($ch);

    if ($httpVersion === CURL_HTTP_VERSION_1_0) {
        $result['protocol'] = 'HTTP/1.0';
    } elseif ($httpVersion === CURL_HTTP_VERSION_1_1) {
        $result['protocol'] = 'HTTP/1.1';
    } elseif ($httpVersion === CURL_HTTP_VERSION_2_0) {
        $result['http2'] = true;
        $result['protocol'] = 'HTTP/2';
    } elseif (defined('CURL_HTTP_VERSION_3') && $httpVersion === CURL_HTTP_VERSION_3) {
        $result['http3'] = true;
        $result['protocol'] = 'HTTP/3';
    }

    // Check for HTTP/3 via Alt-Svc header
    if ($response && preg_match('/alt-svc:\s*([^\r\n]+)/i', $response, $m)) {
        if (stripos($m[1], 'h3') !== false) {
            $result['http3'] = true;
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  IPv6 readiness check (Issue #113)
// ═══════════════════════════════════════════════════════════════════

function checkIpv6Readiness(string $domain): array {
    $result = ['has_aaaa' => false, 'aaaa_records' => [], 'reachable' => null];

    $records = @dns_get_record($domain, DNS_AAAA);
    if ($records) {
        foreach ($records as $rec) {
            if (isset($rec['ipv6'])) {
                $result['has_aaaa'] = true;
                $result['aaaa_records'][] = $rec['ipv6'];
            }
        }
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  DNS resolution & HTTP response time (Issue #114)
// ═══════════════════════════════════════════════════════════════════

function measureResponseTimes(string $domain): array {
    $result = ['dns_ms' => null, 'ttfb_ms' => null, 'total_ms' => null];

    // Issue #197: vet before connecting; return the same default/failure shape without
    // connecting if the host doesn't resolve to a public address. Note: pinning the
    // connection via CURLOPT_RESOLVE means curl skips its own DNS lookup for this
    // request, so CURLINFO_NAMELOOKUP_TIME (dns_ms below) now reflects that skipped
    // lookup (~0ms) rather than a live resolution — an accepted trade-off of the fix.
    $vet = resolveAndVetHost($domain);
    if ($vet === null) {
        return $result;
    }

    $ch = curl_init('https://' . $domain);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_NOBODY => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT => 'mwWhoIs',
        CURLOPT_RESOLVE => [$domain . ':443:' . bracketIp($vet['ip']), $domain . ':80:' . bracketIp($vet['ip'])],
    ]);
    curl_exec($ch);

    if (curl_errno($ch) === 0) {
        $result['dns_ms'] = round(curl_getinfo($ch, CURLINFO_NAMELOOKUP_TIME) * 1000);
        $result['ttfb_ms'] = round(curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME) * 1000);
        $result['total_ms'] = round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000);
    }
    curl_close($ch);

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Nameserver diversity check (Issue #115)
// ═══════════════════════════════════════════════════════════════════

function checkNsDiversity(string $domain): array {
    $result = ['nameservers' => [], 'unique_networks' => 0, 'diverse' => true, 'warning' => null];

    $nsRecords = @dns_get_record($domain, DNS_NS);
    if (!$nsRecords) {
        return $result;
    }

    $networks = [];
    foreach ($nsRecords as $rec) {
        $ns = $rec['target'] ?? '';
        if (!$ns) {
            continue;
        }

        $nsIp = @gethostbyname($ns);
        $network = ($nsIp !== $ns) ? implode('.', array_slice(explode('.', $nsIp), 0, 2)) . '.x.x' : 'unknown';
        $result['nameservers'][] = ['hostname' => $ns, 'ip' => ($nsIp !== $ns) ? $nsIp : null, 'network' => $network];
        $networks[$network] = true;
    }

    $result['unique_networks'] = count($networks);
    if (count($result['nameservers']) > 1 && $result['unique_networks'] <= 1) {
        $result['diverse'] = false;
        $result['warning'] = 'All nameservers are in the same network — single point of failure risk';
    }

    return $result;
}


// ═══════════════════════════════════════════════════════════════════
//  Domain name suggestions (Issue #116, #164)
// ═══════════════════════════════════════════════════════════════════

/**
 * Curated list of popular TLDs checked when offering alternatives.
 * Ordered roughly by demand — generic first, then tech/new gTLDs, then ccTLDs.
 */
function getPopularTlds(): array {
    return [
        // Classic generic
        'com', 'net', 'org', 'info', 'biz', 'pro',
        // Tech / new gTLDs
        'io', 'co', 'dev', 'app', 'ai', 'tech', 'cloud', 'online', 'site', 'store', 'xyz', 'me',
        // UK / EU
        'co.uk', 'uk', 'eu', 'de', 'fr', 'es', 'it', 'nl', 'ch',
        // Americas / APAC
        'us', 'ca', 'au', 'nz', 'in', 'jp',
    ];
}

/**
 * Extract the left-hand label (SLD) from a domain, honouring multi-part
 * suffixes like co.uk. For "acme.co.uk" this returns "acme".
 */
function splitDomainLabel(string $domain): array {
    $domain = strtolower($domain);
    $registrable = extractRegistrableDomain($domain);
    $parts = explode('.', $registrable, 2);
    $label = $parts[0];
    $tld = $parts[1] ?? '';
    return ['label' => $label, 'tld' => $tld];
}

/**
 * Fast per-TLD availability check using parallel RDAP requests with caching.
 * Falls back to DNS NS presence as a "registered" signal when RDAP is unreachable.
 *
 * Returns an array of ['domain', 'tld', 'availability', 'cached'] entries,
 * one per TLD (excluding the current TLD).
 */
function checkAlternativeTldAvailability(string $label, string $currentTld, array $tlds): array {
    $results = [];
    $pending = [];

    foreach ($tlds as $tld) {
        if ($tld === $currentTld) {
            continue;
        }
        $candidate = $label . '.' . $tld;
        $cached = getCached('alt:' . $candidate);
        if ($cached !== null) {
            $results[$candidate] = ['domain' => $candidate, 'tld' => $tld, 'availability' => $cached, 'cached' => true];
            continue;
        }
        $pending[$candidate] = $tld;
    }

    if (!empty($pending) && function_exists('curl_multi_init')) {
        $mh = curl_multi_init();
        $handles = [];

        foreach ($pending as $candidate => $tld) {
            $ch = curl_init('https://rdap.org/domain/' . urlencode($candidate));
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS      => 3,
                CURLOPT_TIMEOUT        => 4,
                CURLOPT_CONNECTTIMEOUT => 2,
                CURLOPT_HTTPHEADER     => ['Accept: application/rdap+json'],
                CURLOPT_USERAGENT      => 'mwWhoisLookup/1.0',
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
                CURLOPT_NOSIGNAL       => 1,
            ]);
            curl_multi_add_handle($mh, $ch);
            $handles[$candidate] = $ch;
        }

        $running = null;
        do {
            curl_multi_exec($mh, $running);
            if ($running) {
                curl_multi_select($mh, 1.0);
            }
        } while ($running > 0);

        foreach ($handles as $candidate => $ch) {
            $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $body = curl_multi_getcontent($ch);
            curl_multi_remove_handle($mh, $ch);
            curl_close($ch);

            $availability = 'unknown';
            if ($code === 404) {
                // rdap.org also returns a bare 404 for TLDs it has no RDAP
                // endpoint for at all — not just for genuinely unregistered
                // names (Issue #215). Confirm against live NS records before
                // trusting the 404; if the name resolves, downgrade to
                // 'unknown' rather than wrongly reporting it available.
                $availability = @checkdnsrr($candidate, 'NS') ? 'unknown' : 'available';
            } elseif ($code >= 200 && $code < 300 && $body) {
                $data = json_decode($body, true);
                if (is_array($data) && isset($data['ldhName'])) {
                    $availability = 'registered';
                } elseif (is_array($data) && isset($data['errorCode']) && (int)$data['errorCode'] === 404) {
                    $availability = 'available';
                }
            }

            // DNS NS presence is strong "registered" evidence when RDAP is inconclusive
            if ($availability === 'unknown' && @checkdnsrr($candidate, 'NS')) {
                $availability = 'registered';
            }

            $results[$candidate] = [
                'domain' => $candidate,
                'tld' => $pending[$candidate],
                'availability' => $availability,
                'cached' => false,
            ];
            setCache('alt:' . $candidate, $availability);
        }

        curl_multi_close($mh);
    } elseif (!empty($pending)) {
        // curl_multi not available — fall back to DNS NS check only
        foreach ($pending as $candidate => $tld) {
            $availability = @checkdnsrr($candidate, 'NS') ? 'registered' : 'unknown';
            $results[$candidate] = [
                'domain' => $candidate,
                'tld' => $tld,
                'availability' => $availability,
                'cached' => false,
            ];
            setCache('alt:' . $candidate, $availability);
        }
    }

    // Preserve input TLD order
    $ordered = [];
    foreach ($tlds as $tld) {
        if ($tld === $currentTld) {
            continue;
        }
        $candidate = $label . '.' . $tld;
        if (isset($results[$candidate])) {
            $ordered[] = $results[$candidate];
        }
    }
    return $ordered;
}

/**
 * Back-compat wrapper — returns a flat list of available candidate domains
 * (up to $limit entries). Used by older UI code paths.
 */
function suggestAlternativeDomains(string $domain, int $limit = 5): array {
    $split = splitDomainLabel($domain);
    if ($split['label'] === '' || $split['tld'] === '') {
        return [];
    }
    $results = checkAlternativeTldAvailability($split['label'], $split['tld'], getPopularTlds());
    $suggestions = [];
    foreach ($results as $r) {
        if ($r['availability'] === 'available') {
            $suggestions[] = $r['domain'];
            if (count($suggestions) >= $limit) {
                break;
            }
        }
    }
    return $suggestions;
}

/**
 * Full TLD availability grid for the requested domain. Returns a structured
 * payload for the frontend availability grid and JSON API.
 */
function getTldAvailabilityGrid(string $domain): array {
    $split = splitDomainLabel($domain);
    if ($split['label'] === '' || $split['tld'] === '') {
        return ['label' => '', 'current_tld' => '', 'results' => []];
    }
    return [
        'label' => $split['label'],
        'current_tld' => $split['tld'],
        'results' => checkAlternativeTldAvailability($split['label'], $split['tld'], getPopularTlds()),
    ];
}


// ═══════════════════════════════════════════════════════════════════
//  TLD reference list (Issue — /tlds page)
// ═══════════════════════════════════════════════════════════════════

/**
 * Loads the IANA TLD list from disk (populated by updateTldDataIfNeeded()).
 * Returns an array of lowercase TLDs with the leading dot stripped.
 */
function loadIanaTldList(): array {
    if (!file_exists(IANA_TLD_PATH)) {
        return [];
    }
    $lines = file(IANA_TLD_PATH, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $tlds = [];
    foreach ($lines as $line) {
        $line = trim($line);
        if ($line === '' || str_starts_with($line, '#')) {
            continue;
        }
        // IANA file is UPPERCASE A-label; normalise to lowercase.
        // Keep Punycode (xn--...) as-is; front-end can render Unicode form separately.
        $tlds[] = strtolower($line);
    }
    sort($tlds, SORT_STRING);
    return $tlds;
}

/**
 * Classify a TLD into one of: country (ccTLD), sponsored, generic (legacy gTLD),
 * infrastructure, or new_gtld. Classification is heuristic but matches IANA
 * categories closely enough for reference display purposes.
 */
function classifyTld(string $tld): string {
    $tld = strtolower(ltrim($tld, '.'));

    if ($tld === 'arpa') {
        return 'infrastructure';
    }

    static $sponsored = [
        'aero', 'asia', 'cat', 'coop', 'edu', 'gov', 'int', 'jobs',
        'mil', 'mobi', 'museum', 'post', 'tel', 'travel', 'xxx',
    ];
    if (in_array($tld, $sponsored, true)) {
        return 'sponsored';
    }

    static $generic = ['com', 'net', 'org', 'info', 'biz', 'name', 'pro'];
    if (in_array($tld, $generic, true)) {
        return 'generic';
    }

    // ccTLDs: two-letter ASCII OR Punycode two-letter IDN ccTLDs (xn-- …).
    // IANA's Punycode country-codes decode to a single-label country TLD.
    if (preg_match('/^[a-z]{2}$/', $tld)) {
        return 'country';
    }
    if (str_starts_with($tld, 'xn--')) {
        // IDN ccTLDs are flagged as country; IDN gTLDs will be misclassified
        // here but that is acceptable for a reference view.
        return 'country';
    }

    return 'new_gtld';
}

/**
 * Returns the IANA TLD list grouped by category, with counts.
 * Categories: generic, country, sponsored, new_gtld, infrastructure.
 */
function getTldsByCategory(): array {
    $tlds = loadIanaTldList();
    $groups = [
        'generic'        => [],
        'country'        => [],
        'sponsored'      => [],
        'new_gtld'       => [],
        'infrastructure' => [],
    ];
    foreach ($tlds as $tld) {
        $cat = classifyTld($tld);
        $groups[$cat][] = $tld;
    }
    return $groups;
}


// ═══════════════════════════════════════════════════════════════════
//  Technology stack detection (Issue #124)
// ═══════════════════════════════════════════════════════════════════

function detectTechStack(string $domain): ?array {
    // Issue #197: vet before connecting. The redirect-following fetch below re-vets
    // each hop itself (see fetchViaVettedCurl()), but bail out up front if the domain
    // itself doesn't resolve to a public address.
    $vet = resolveAndVetHost($domain);
    if ($vet === null) {
        return null;
    }

    // Issue #192: needs response headers + redirect-following, which httpFetch()'s
    // SSRF-safe/body-only contract doesn't support — use curl directly here with the
    // same hard TOTAL timeout cap (idle-only stream timeouts let a slow response hang).
    // Issue #197: CURLOPT_FOLLOWLOCATION is no longer used (it would connect straight
    // to whatever host a Location header names, completely unvetted); fetchViaVettedCurl()
    // walks redirects itself, re-vetting + re-pinning every hop.
    $headers = [];
    $html = null;
    $fetch = fetchViaVettedCurl('https://' . $domain, [
        CURLOPT_TIMEOUT        => 5,       // TOTAL time cap
        CURLOPT_CONNECTTIMEOUT => 2,
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_USERAGENT      => 'mwWhoIs',
        CURLOPT_MAXFILESIZE    => 3145728, // 3 MB cap
    ]);
    if ($fetch !== null) {
        $html = $fetch['body'];
        foreach (preg_split('/\r\n|\n/', trim($fetch['headers'])) as $h) {
            $parts = explode(':', $h, 2);
            if (count($parts) === 2) {
                $headers[strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }
    }
    // Issue #197: the old curl-unavailable fallback (a plain stream-context
    // file_get_contents()) had no way to pin the connection to the vetted IP — it would
    // re-resolve $domain itself, reopening the exact rebinding window this gate closes.
    // If curl isn't available, fetchViaVettedCurl() returns null and we simply have no
    // headers/html to analyse, rather than silently falling back to an unpinned fetch.

    $techs = [];

    // Server
    if (!empty($headers['server'])) {
        $techs[] = ['category' => 'Server', 'name' => $headers['server']];
    }
    if (!empty($headers['x-powered-by'])) {
        $techs[] = ['category' => 'Framework', 'name' => $headers['x-powered-by']];
    }

    if ($html) {
        // CMS detection
        if (str_contains(strtolower($html), 'wp-content')  || str_contains(strtolower($html), 'wordpress') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'WordPress'];
        } elseif (str_contains(strtolower($html), 'joomla') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Joomla'];
        } elseif (str_contains(strtolower($html), 'drupal') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Drupal'];
        } elseif (str_contains(strtolower($html), 'shopify') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Shopify'];
        } elseif (str_contains(strtolower($html), 'squarespace') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Squarespace'];
        } elseif (str_contains(strtolower($html), 'wix.com') ) {
            $techs[] = ['category' => 'CMS', 'name' => 'Wix'];
        }

        // JS frameworks
        if (str_contains(strtolower($html), 'react')  || str_contains(strtolower($html), '__next_data__') ) {
            $techs[] = ['category' => 'JS Framework', 'name' => 'React'];
        }
        if (str_contains(strtolower($html), 'vue')  && str_contains(strtolower($html), 'data-v-') ) {
            $techs[] = ['category' => 'JS Framework', 'name' => 'Vue.js'];
        }
        if (str_contains(strtolower($html), 'angular')  || str_contains(strtolower($html), 'ng-') ) {
            $techs[] = ['category' => 'JS Framework', 'name' => 'Angular'];
        }

        // CDN
        if (str_contains(strtolower($html), 'cloudflare')  || !empty($headers['cf-ray'])) {
            $techs[] = ['category' => 'CDN', 'name' => 'Cloudflare'];
        }
        if (str_contains(strtolower($html), 'cdn.jsdelivr.net') ) {
            $techs[] = ['category' => 'CDN', 'name' => 'jsDelivr'];
        }
        if (str_contains(strtolower($html), 'cloudfront') ) {
            $techs[] = ['category' => 'CDN', 'name' => 'CloudFront'];
        }
        if (str_contains(strtolower($html), 'akamai') ) {
            $techs[] = ['category' => 'CDN', 'name' => 'Akamai'];
        }

        // Analytics
        if (str_contains(strtolower($html), 'google-analytics')  || str_contains(strtolower($html), 'gtag')  || str_contains(strtolower($html), 'ga-') ) {
            $techs[] = ['category' => 'Analytics', 'name' => 'Google Analytics'];
        }
        if (str_contains(strtolower($html), 'matomo')  || str_contains(strtolower($html), 'piwik') ) {
            $techs[] = ['category' => 'Analytics', 'name' => 'Matomo'];
        }

        // Meta generator
        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)/i', $html, $m)) {
            $techs[] = ['category' => 'Generator', 'name' => $m[1]];
        }
    }

    return count($techs) > 0 ? $techs : null;
}


// ═══════════════════════════════════════════════════════════════════
//  Robots.txt & sitemap.xml analysis (Issue #125)
// ═══════════════════════════════════════════════════════════════════

function analyseRobotsTxt(string $domain): ?array {
    $result = ['robots_found' => false, 'sitemap_found' => false, 'disallowed' => [], 'sitemaps' => [], 'crawl_delay' => null];

    // Issue #197: vet before connecting; pin BOTH fetches below to the checked IP.
    // Vetting once up front (instead of once per fetch) also means both requests hit
    // the exact same checked address — no gap between the two calls for a rebinding
    // attacker to swap the DNS answer.
    $vet = resolveAndVetHost($domain);
    if ($vet === null) {
        return null;
    }
    $resolvePin = [$domain . ':443:' . bracketIp($vet['ip']), $domain . ':80:' . bracketIp($vet['ip'])];

    $robots = httpFetch('https://' . $domain . '/robots.txt', ['timeout' => 5, 'resolve' => $resolvePin]);
    if ($robots && stripos($robots, '<html') === false) {
        $result['robots_found'] = true;
        foreach (explode("\n", $robots) as $line) {
            $line = trim($line);
            if (str_starts_with(strtolower($line), 'disallow:')) {
                $path = trim(substr($line, 9));
                if ($path) {
                    $result['disallowed'][] = $path;
                }
            } elseif (str_starts_with(strtolower($line), 'sitemap:')) {
                $result['sitemaps'][] = trim(substr($line, 8));
            } elseif (str_starts_with(strtolower($line), 'crawl-delay:')) {
                $result['crawl_delay'] = (int)trim(substr($line, 12));
            }
        }
        $result['disallowed'] = array_slice(array_unique($result['disallowed']), 0, 20);
    }

    // Check sitemap.xml — Issue #197: replaced get_headers()'s stream-context wrapper
    // (which re-resolves the hostname itself, with no way to pin it) with a curl HEAD
    // request pinned to the already-vetted IP.
    $sitemapStatus = null;
    if (function_exists('curl_init')) {
        $ch = curl_init('https://' . $domain . '/sitemap.xml');
        $chOpts = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_USERAGENT      => 'mwWhoIs',
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_RESOLVE        => $resolvePin,
        ];
        if (defined('CURLOPT_PROTOCOLS')) { $chOpts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) { $chOpts[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTP | CURLPROTO_HTTPS; }
        curl_setopt_array($ch, $chOpts);
        curl_exec($ch);
        $sitemapStatus = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
    }
    if ($sitemapStatus === 200) {
        $result['sitemap_found'] = true;
        if (!in_array('https://' . $domain . '/sitemap.xml', $result['sitemaps'])) {
            $result['sitemaps'][] = 'https://' . $domain . '/sitemap.xml';
        }
    }

    return ($result['robots_found'] || $result['sitemap_found']) ? $result : null;
}


// ═══════════════════════════════════════════════════════════════════
//  DNS propagation checker (Issue #126)
// ═══════════════════════════════════════════════════════════════════

function checkDnsPropagation(string $domain, bool $full = false): array {
    global $config;

    $resolvers = $config['dns_resolvers'] ?? [];
    $enabled = [];
    foreach ($resolvers as $r) {
        if (!empty($r['enabled'])) {
            $enabled[] = $r;
        }
    }

    // Issue #194: curate the default panel down from the full ~187-entry enabled list.
    // Callers that explicitly want everything (the dns_propagation_only refresh
    // endpoint, given `full=1`) pass $full = true.
    if (!$full) {
        $max = $config['dns_propagation_max'] ?? 25;
        $enabled = array_slice($enabled, 0, $max);
    }

    // Run all dig queries in parallel using temp files
    $tmpDir = sys_get_temp_dir();
    $tmpFiles = [];
    foreach ($enabled as $i => $resolver) {
        $tmpFile = $tmpDir . DIRECTORY_SEPARATOR . 'dns_prop_' . getmypid() . '_' . $i;
        $tmpFiles[$i] = $tmpFile;
        // Issue #194: write to a .part file and mv it into place once dig has actually
        // finished. The previous `dig ... > $tmpFile` redirection CREATES $tmpFile the
        // instant the shell forks the background job — before dig has run at all — so
        // file_exists($tmpFile) was true immediately and the poll loop below exited on
        // its very first check, returning mostly-empty results. Wrapped in a subshell
        // so the WHOLE sequence backgrounds together: without the parens, `&` only
        // applies to the last command in a `;`-separated list, so dig itself would run
        // synchronously and every resolver would be queried one at a time instead of
        // in parallel.
        $cmd = '( dig @' . escapeshellarg($resolver['ip']) . ' +short +time=2 +tries=1 A '
             . escapeshellarg($domain) . ' > ' . escapeshellarg($tmpFile . '.part') . ' 2>/dev/null; mv '
             . escapeshellarg($tmpFile . '.part') . ' ' . escapeshellarg($tmpFile) . ' ) &';
        @exec($cmd);
    }

    // Wait for all background processes (max 4s total — unchanged overall time cap)
    usleep(500000);
    $waited = 0;
    while ($waited < 35) {
        $allDone = true;
        foreach ($tmpFiles as $f) {
            if (!file_exists($f)) {
                $allDone = false;
                break;
            }
        }
        if ($allDone) break;
        usleep(100000);
        $waited++;
    }

    // Collect results
    $results = [];
    foreach ($enabled as $i => $resolver) {
        $output = @file_get_contents($tmpFiles[$i]);
        @unlink($tmpFiles[$i]);
        @unlink($tmpFiles[$i] . '.part'); // in case a resolver never finished within the time cap
        $ips = $output ? array_filter(array_map('trim', explode("\n", trim($output)))) : [];
        $results[] = [
            'id' => $resolver['id'] ?? $i,
            'resolver' => $resolver['name'],
            'ip' => $resolver['ip'],
            'country_code' => $resolver['country_code'] ?? '',
            'location' => $resolver['location'] ?? '',
            'type' => $resolver['type'] ?? 'standard',
            'answers' => $ips,
        ];
    }

    // Check consistency — sort each answer set so different ordering is not flagged
    $allAnswers = array_map(function ($r) {
        $sorted = $r['answers'];
        sort($sorted);
        return implode(',', $sorted);
    }, $results);
    $consistent = count(array_unique($allAnswers)) <= 1;

    return ['resolvers' => $results, 'consistent' => $consistent];
}


// ═══════════════════════════════════════════════════════════════════
//  Security score aggregation (Issue #128)
// ═══════════════════════════════════════════════════════════════════

function calculateSecurityScore(array $data): array {
    $details = [];

    // HTTPS (via SSL info)
    $httpsPass = !empty($data['ssl']);
    $details[] = [
        'name' => 'HTTPS / SSL',
        'status' => $httpsPass ? 'pass' : 'fail',
        'info' => $httpsPass ? 'Valid SSL certificate detected' : 'No SSL certificate found',
        'recommendation' => $httpsPass ? null : 'Install an SSL/TLS certificate and enforce HTTPS',
        'guide' => $httpsPass ? null : 'https://letsencrypt.org/getting-started/',
    ];

    // HSTS
    $hstsPass = false;
    if (!empty($data['http_headers'])) {
        foreach ($data['http_headers']['headers'] ?? [] as $h) {
            if ($h['header'] === 'HSTS' && $h['present']) {
                $hstsPass = true;
                break;
            }
        }
    }
    $details[] = [
        'name' => 'HSTS',
        'status' => $hstsPass ? 'pass' : 'fail',
        'info' => $hstsPass ? 'Strict-Transport-Security header present' : 'HSTS header not found',
        'recommendation' => $hstsPass ? null : 'Add a Strict-Transport-Security header to enforce HTTPS connections',
        'guide' => $hstsPass ? null : 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security',
    ];

    // DNSSEC
    $dnssecPass = !empty($data['dnssec']['signed']);
    $details[] = [
        'name' => 'DNSSEC',
        'status' => $dnssecPass ? 'pass' : 'fail',
        'info' => $dnssecPass ? 'DNSSEC signatures verified' : 'DNSSEC not enabled',
        'recommendation' => $dnssecPass ? null : 'Enable DNSSEC with your DNS provider to protect against DNS spoofing',
        'guide' => $dnssecPass ? null : 'https://www.icann.org/resources/pages/dnssec-what-is-it-why-is-it-important-2019-03-05-en',
    ];

    // SPF
    $spfPass = !empty($data['email_security']['spf']['found']);
    $details[] = [
        'name' => 'SPF',
        'status' => $spfPass ? 'pass' : 'fail',
        'info' => $spfPass ? 'SPF record found' : 'No SPF record',
        'recommendation' => $spfPass ? null : 'Add an SPF TXT record to specify authorised mail servers',
        'guide' => $spfPass ? null : 'https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-spf-record/',
    ];

    // DMARC
    $dmarcPass = !empty($data['email_security']['dmarc']['found']);
    $details[] = [
        'name' => 'DMARC',
        'status' => $dmarcPass ? 'pass' : 'fail',
        'info' => $dmarcPass ? 'DMARC policy found' : 'No DMARC policy',
        'recommendation' => $dmarcPass ? null : 'Add a DMARC TXT record to protect against email spoofing',
        'guide' => $dmarcPass ? null : 'https://dmarc.org/overview/',
    ];

    // DKIM
    $dkimPass = !empty($data['email_security']['dkim']['found']);
    $details[] = [
        'name' => 'DKIM',
        'status' => $dkimPass ? 'pass' : 'warn',
        'info' => $dkimPass ? 'DKIM selector found' : 'DKIM not detected (common selectors checked)',
        'recommendation' => $dkimPass ? null : 'Configure DKIM signing with your email provider',
        'guide' => $dkimPass ? null : 'https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-dkim-record/',
    ];

    // MTA-STS
    $mtaStsPass = !empty($data['mta_sts']['found']);
    $details[] = [
        'name' => 'MTA-STS',
        'status' => $mtaStsPass ? 'pass' : 'warn',
        'info' => $mtaStsPass ? 'MTA-STS policy published' : 'No MTA-STS policy',
        'recommendation' => $mtaStsPass ? null : 'Publish an MTA-STS policy to enforce TLS for inbound email',
        'guide' => $mtaStsPass ? null : 'https://www.hardenize.com/blog/mta-sts/',
    ];

    // TLS 1.2+ only (no 1.0/1.1)
    $tlsPass = !empty($data['tls_audit']) && empty($data['tls_audit']['insecure']);
    $details[] = [
        'name' => 'TLS Version',
        'status' => $tlsPass ? 'pass' : 'fail',
        'info' => $tlsPass ? 'Only TLS 1.2+ supported' : 'Insecure TLS versions (1.0/1.1) accepted',
        'recommendation' => $tlsPass ? null : 'Disable TLS 1.0 and 1.1 on your web server',
        'guide' => $tlsPass ? null : 'https://ssl-config.mozilla.org/',
    ];

    // Not on blocklists
    $blPass = empty($data['spamhaus']['listed']);
    $details[] = [
        'name' => 'Blocklist',
        'status' => $blPass ? 'pass' : 'fail',
        'info' => $blPass ? 'Not listed on Spamhaus' : 'Listed on Spamhaus blocklist',
        'recommendation' => $blPass ? null : 'Investigate and resolve the blocklist listing at spamhaus.org',
        'guide' => $blPass ? null : 'https://www.spamhaus.org/blocklists/do-not-block/',
    ];

    // CAA records
    $caaPass = !empty($data['caa_records']['found']);
    $details[] = [
        'name' => 'CAA Records',
        'status' => $caaPass ? 'pass' : 'warn',
        'info' => $caaPass ? 'CAA records restrict certificate issuance' : 'No CAA records found',
        'recommendation' => $caaPass ? null : 'Add CAA DNS records to control which CAs can issue certificates',
        'guide' => $caaPass ? null : 'https://letsencrypt.org/docs/caa/',
    ];

    // No malware/phishing
    $malwarePass = empty($data['urlhaus']['urls_total']) || $data['urlhaus']['urls_total'] === 0;
    $details[] = [
        'name' => 'Malware / Phishing',
        'status' => $malwarePass ? 'pass' : 'fail',
        'info' => $malwarePass ? 'No known malware URLs' : 'Malware URLs associated with this domain',
        'recommendation' => $malwarePass ? null : 'Scan your site for compromised files and remove malicious content',
        'guide' => $malwarePass ? null : 'https://developers.google.com/web/fundamentals/security/hacked/',
    ];

    $passed = 0;
    foreach ($details as $d) {
        if ($d['status'] === 'pass') {
            $passed++;
        }
    }
    $total = count($details);
    $pct = $total > 0 ? round(($passed / $total) * 100) : 0;
    $grade = 'F';
    if ($pct >= 90) {
        $grade = 'A';
    } elseif ($pct >= 75) {
        $grade = 'B';
    } elseif ($pct >= 60) {
        $grade = 'C';
    } elseif ($pct >= 45) {
        $grade = 'D';
    } elseif ($pct >= 30) {
        $grade = 'E';
    }

    return ['grade' => $grade, 'score' => $pct, 'passed' => $passed, 'total' => $total, 'details' => $details];
}


// ═══════════════════════════════════════════════════════════════════
//  Multi-DNSBL check (Issue #133)
// ═══════════════════════════════════════════════════════════════════

function checkMultiDnsbl(string $ip): array {
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return ['listed' => false, 'lists' => []];
    }

    $reversed = implode('.', array_reverse(explode('.', $ip)));
    // Issue #191: dnsbl.sorbs.net (SORBS, decommissioned 2024) and cbl.abuseat.org
    // (CBL, folded into Spamhaus ZEN) are dead zones that just time out every lookup.
    $zones = [
        'zen.spamhaus.org' => 'Spamhaus ZEN',
        'b.barracudacentral.org' => 'Barracuda',
        'bl.spamcop.net' => 'SpamCop',
        'dnsbl-1.uceprotect.net' => 'UCEPROTECT L1',
        'dyna.spamrats.com' => 'SpamRATS',
        'bl.mailspike.net' => 'Mailspike',
    ];

    $listed = [];
    foreach ($zones as $zone => $label) {
        $result = @dns_get_record($reversed . '.' . $zone, DNS_A);
        if ($result && count($result) > 0) {
            $listed[] = ['zone' => $zone, 'label' => $label];
        }
    }

    return ['ip' => $ip, 'listed' => count($listed) > 0, 'total_checked' => count($zones), 'lists' => $listed];
}
