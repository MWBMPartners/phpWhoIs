<?php

use PHPUnit\Framework\TestCase;

/**
 * Issue #196 Step 2 — SSRF-safe curl_multi batch helper.
 *
 * These tests prove curlMultiHandleOpts()/curlMultiBatch() preserve every
 * #197 SSRF invariant WITHOUT any network access:
 *   - a non-80/443 port is rejected (no connection attempted);
 *   - a private/reserved/loopback/metadata IP host with no vetting is
 *     rejected (no connection attempted);
 *   - a private/reserved 'pin_ip' is rejected even if the hostname itself
 *     looks benign;
 *   - CURLOPT_FOLLOWLOCATION is always false and CURLOPT_PROTOCOLS /
 *     CURLOPT_REDIR_PROTOCOLS are always restricted to http/https;
 *   - a supplied 'pin_ip' is wired into CURLOPT_RESOLVE for both :443 and
 *     :80, bracketed for IPv6.
 *
 * curlMultiHandleOpts() is a pure function (builds an option array, never
 * touches curl/the network), so every rejection case can be asserted on
 * directly — this is the primary evidence for the SSRF invariant. The
 * curlMultiBatch()-level tests only cover the "everything rejected" path
 * (which curlMultiBatch() short-circuits before ever calling
 * curl_multi_init()), so they too require no network access.
 */
class CurlMultiBatchTest extends TestCase
{
    // ═══════════════════════════════════════════════════════════════
    //  curlMultiHandleOpts() — rejection cases (never connect)
    // ═══════════════════════════════════════════════════════════════

    public function testRejectsNonStandardPort(): void
    {
        $result = curlMultiHandleOpts(['url' => 'https://example.com:8080/path']);
        $this->assertFalse($result['ok']);
        $this->assertSame('bad_port', $result['error']);
    }

    public function testRejectsNonStandardPortEvenWithPin(): void
    {
        // A pin does NOT rescue a non-standard port — CURLOPT_RESOLVE pins
        // are host:PORT-scoped and only cover 80/443 (see
        // fetchViaVettedCurl()'s doc comment on the same restriction).
        $result = curlMultiHandleOpts(['url' => 'https://example.com:8443/', 'pin_ip' => '1.1.1.1']);
        $this->assertFalse($result['ok']);
        $this->assertSame('bad_port', $result['error']);
    }

    /**
     * @dataProvider privateIpLiteralHosts
     */
    public function testRejectsPrivateOrReservedIpLiteralHostWithNoPin(string $urlHost): void
    {
        $result = curlMultiHandleOpts(['url' => 'http://' . $urlHost . '/probe']);
        $this->assertFalse($result['ok'], "Expected {$urlHost} (unpinned literal host) to be rejected");
        $this->assertSame('private_ip', $result['error']);
    }

    public static function privateIpLiteralHosts(): array
    {
        return [
            'loopback' => ['127.0.0.1'],
            'rfc1918-10' => ['10.1.2.3'],
            'rfc1918-192.168' => ['192.168.1.1'],
            'rfc1918-172.16' => ['172.16.0.5'],
            'cloud-metadata' => ['169.254.169.254'],
            'link-local' => ['169.254.1.1'],
            'cgnat' => ['100.64.0.1'],
            // IPv6 literals in a URL are bracketed — parse_url(PHP_URL_HOST)
            // returns them WITH the brackets attached (e.g. "[::1]"), which is
            // the exact case that must be un-bracketed before the private-IP
            // check runs, or a private IPv6 literal URL would silently slip
            // through unpinned (see curlMultiHandleOpts()'s $hostForIpCheck).
            'ipv6-loopback' => ['[::1]'],
            'ipv6-ula' => ['[fc00::1]'],
            'ipv6-link-local' => ['[fe80::1]'],
        ];
    }

    /**
     * @dataProvider privateIpPins
     */
    public function testRejectsPrivateOrReservedPinIp(string $pinIp): void
    {
        // Hostname itself looks benign — the vetted pin is what's bad.
        $result = curlMultiHandleOpts(['url' => 'https://internal-looking-host.example/', 'pin_ip' => $pinIp]);
        $this->assertFalse($result['ok'], "Expected pin_ip {$pinIp} to be rejected");
        $this->assertSame('private_ip', $result['error']);
    }

    public static function privateIpPins(): array
    {
        return [
            'loopback' => ['127.0.0.1'],
            'rfc1918' => ['10.0.0.5'],
            'metadata' => ['169.254.169.254'],
            'ipv6-loopback' => ['::1'],
            'ipv4-mapped-loopback' => ['::ffff:127.0.0.1'],
        ];
    }

    public function testRejectsUnparsableUrl(): void
    {
        $result = curlMultiHandleOpts(['url' => '']);
        $this->assertFalse($result['ok']);
        $this->assertSame('unparsable_url', $result['error']);
    }

    public function testRejectsNonHttpScheme(): void
    {
        $result = curlMultiHandleOpts(['url' => 'ftp://example.com/file']);
        $this->assertFalse($result['ok']);
        $this->assertSame('bad_scheme', $result['error']);
    }

    // ═══════════════════════════════════════════════════════════════
    //  curlMultiHandleOpts() — accepted cases + invariant assertions
    // ═══════════════════════════════════════════════════════════════

    public function testAllowsFixedThirdPartyHostWithNoPin(): void
    {
        // A fixed, non-user-controlled API host (per the #197 contract) is
        // allowed through unpinned — curl resolves it normally, exactly like
        // httpFetch()/checkVirusTotal() etc. already do today.
        $result = curlMultiHandleOpts(['url' => 'https://www.virustotal.com/api/v3/domains/example.com']);
        $this->assertTrue($result['ok']);
        $this->assertArrayNotHasKey(CURLOPT_RESOLVE, $result['opts']);
    }

    public function testAllowsPublicIpLiteralHostWithNoPin(): void
    {
        $result = curlMultiHandleOpts(['url' => 'http://1.1.1.1/']);
        $this->assertTrue($result['ok']);
    }

    public function testFollowLocationIsAlwaysFalse(): void
    {
        $result = curlMultiHandleOpts(['url' => 'https://example.com/']);
        $this->assertTrue($result['ok']);
        $this->assertArrayHasKey(CURLOPT_FOLLOWLOCATION, $result['opts']);
        $this->assertFalse($result['opts'][CURLOPT_FOLLOWLOCATION]);
    }

    public function testProtocolsAreRestrictedToHttpAndHttps(): void
    {
        $result = curlMultiHandleOpts(['url' => 'https://example.com/']);
        $this->assertTrue($result['ok']);
        if (defined('CURLOPT_PROTOCOLS')) {
            $this->assertSame(CURLPROTO_HTTP | CURLPROTO_HTTPS, $result['opts'][CURLOPT_PROTOCOLS]);
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS')) {
            $this->assertSame(CURLPROTO_HTTP | CURLPROTO_HTTPS, $result['opts'][CURLOPT_REDIR_PROTOCOLS]);
        }
    }

    public function testPinIpIsWiredIntoCurloptResolveForBothPorts(): void
    {
        $result = curlMultiHandleOpts(['url' => 'https://user-domain.example/', 'pin_ip' => '1.1.1.1']);
        $this->assertTrue($result['ok']);
        $this->assertSame(
            ['user-domain.example:443:1.1.1.1', 'user-domain.example:80:1.1.1.1'],
            $result['opts'][CURLOPT_RESOLVE]
        );
    }

    public function testPinIpv6IsBracketedInCurloptResolve(): void
    {
        // 2606:4700:4700::1111 — a stable public IPv6 address (Cloudflare
        // DNS), used purely as a syntactically-valid PUBLIC IPv6 literal.
        $publicV6 = '2606:4700:4700::1111';
        $result = curlMultiHandleOpts(['url' => 'https://user-domain.example/', 'pin_ip' => $publicV6]);
        $this->assertTrue($result['ok']);
        $this->assertSame(
            ['user-domain.example:443:[' . $publicV6 . ']', 'user-domain.example:80:[' . $publicV6 . ']'],
            $result['opts'][CURLOPT_RESOLVE]
        );
    }

    public function testPostAndHeadersArePassedThrough(): void
    {
        $result = curlMultiHandleOpts([
            'url' => 'https://example.com/',
            'post' => 'a=1&b=2',
            'headers' => ['Content-Type: application/x-www-form-urlencoded'],
        ]);
        $this->assertTrue($result['ok']);
        $this->assertTrue($result['opts'][CURLOPT_POST]);
        $this->assertSame('a=1&b=2', $result['opts'][CURLOPT_POSTFIELDS]);
        $this->assertSame(['Content-Type: application/x-www-form-urlencoded'], $result['opts'][CURLOPT_HTTPHEADER]);
    }

    public function testDefaultPortsAreInferredFromScheme(): void
    {
        // No explicit port in the URL — https implies 443, http implies 80 —
        // both must be accepted (this is the common case for every real caller).
        $https = curlMultiHandleOpts(['url' => 'https://example.com/']);
        $http = curlMultiHandleOpts(['url' => 'http://example.com/']);
        $this->assertTrue($https['ok']);
        $this->assertTrue($http['ok']);
    }

    public function testExplicitStandardPortsAreAccepted(): void
    {
        $https = curlMultiHandleOpts(['url' => 'https://example.com:443/']);
        $http = curlMultiHandleOpts(['url' => 'http://example.com:80/']);
        $this->assertTrue($https['ok']);
        $this->assertTrue($http['ok']);
    }

    // ═══════════════════════════════════════════════════════════════
    //  curlMultiBatch() — never connects for rejected requests
    // ═══════════════════════════════════════════════════════════════

    public function testBatchReturnsRejectionEntryForEveryBadRequestWithoutConnecting(): void
    {
        $requests = [
            'bad_port' => ['url' => 'https://example.com:8080/'],
            'private_literal' => ['url' => 'http://127.0.0.1/admin'],
            'private_pin' => ['url' => 'https://looks-fine.example/', 'pin_ip' => '169.254.169.254'],
        ];

        $start = microtime(true);
        $results = curlMultiBatch($requests, 8);
        $elapsed = microtime(true) - $start;

        // If any of these had actually opened a connection, curl would take
        // meaningfully longer than this (connect timeout, DNS, etc.) — a
        // near-instant return is corroborating evidence that curl_multi_init()
        // was never even reached (curlMultiBatch() returns early when $pending
        // is empty, per its own source).
        $this->assertLessThan(1.0, $elapsed, 'All-rejected batch should return near-instantly with no network I/O');

        $this->assertCount(3, $results);
        foreach ($results as $key => $entry) {
            $this->assertSame(0, $entry['status'], "key={$key} should have status=0 (never connected)");
            $this->assertNull($entry['body'], "key={$key} should have null body (never connected)");
            $this->assertSame(-1, $entry['errno'], "key={$key} should have errno=-1 (rejected before connecting)");
        }
    }

    public function testBatchWithNoRequestsReturnsEmptyArray(): void
    {
        $this->assertSame([], curlMultiBatch([]));
    }

    public function testBatchPreservesRequestKeys(): void
    {
        $results = curlMultiBatch([
            'first' => ['url' => 'ftp://bad-scheme.example/'],
            'second' => ['url' => 'http://10.0.0.1/'],
        ]);
        $this->assertArrayHasKey('first', $results);
        $this->assertArrayHasKey('second', $results);
    }
}
