<?php

use PHPUnit\Framework\TestCase;

/**
 * Issue #196 Step 2 — batched reputation module checks.
 *
 * Proves output-shape parity between the (still-intact) SERIAL check*()
 * functions and the new curlMultiBatch()-driven runReputationModuleChecks()
 * path WITHOUT any live network access, by testing the request-builder and
 * response-parser pure functions each check*() was factored into. Because
 * checkSafeBrowsing()/checkVirusTotal()/etc. now call the exact SAME parser
 * function these tests exercise directly, proving the parser's output shape
 * here is proof for BOTH code paths at once — they cannot drift apart
 * (single source of truth), which is the whole point of the Step 2 refactor.
 *
 * Live network requests are deliberately NOT exercised in this suite — the
 * existing test suite (tests/LookupFunctionsTest.php, tests/ModulesTest.php)
 * makes zero live network calls, and this file preserves that discipline.
 */
class ReputationBatchTest extends TestCase
{
    // ═══════════════════════════════════════════════════════════════
    //  reputationNetworkCheckSpecs() — completeness against the registry
    // ═══════════════════════════════════════════════════════════════

    public function testSpecsCoverEveryNetworkIssuingReputationCheck(): void
    {
        $registryKeys = array_keys(moduleRegistry()['reputation']);
        $specKeys = array_keys(reputationNetworkCheckSpecs());

        // Every registry key except the locally-derived 'hosting_risk' must
        // have a request-builder + response-parser pair.
        $expected = array_values(array_diff($registryKeys, ['hosting_risk']));
        sort($expected);
        sort($specKeys);
        $this->assertSame($expected, $specKeys);
    }

    public function testEverySpecFunctionPairExists(): void
    {
        foreach (reputationNetworkCheckSpecs() as $checkKey => $spec) {
            $this->assertTrue(function_exists($spec['request']), "{$checkKey}: request builder {$spec['request']}() must exist");
            $this->assertTrue(function_exists($spec['parse']), "{$checkKey}: response parser {$spec['parse']}() must exist");
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  Request builders — exact URL/payload/header parity with the
    //  pre-refactor inline curl calls
    // ═══════════════════════════════════════════════════════════════

    public function testSafeBrowsingRequestBuildsExpectedUrlAndPayload(): void
    {
        $req = safeBrowsingRequest('example.com', 'KEY123');
        $this->assertSame('https://safebrowsing.googleapis.com/v4/threatMatches:find?key=KEY123', $req['url']);
        $this->assertSame(['Content-Type: application/json'], $req['headers']);
        $payload = json_decode($req['post'], true);
        $this->assertSame(
            ['http://example.com/', 'https://example.com/'],
            array_column($payload['threatInfo']['threatEntries'], 'url')
        );
    }

    public function testVirusTotalRequestBuildsExpectedUrlAndHeaders(): void
    {
        $req = virusTotalRequest('example.com', 'VTKEY');
        $this->assertSame('https://www.virustotal.com/api/v3/domains/example.com', $req['url']);
        $this->assertSame(['x-apikey: VTKEY'], $req['headers']);
    }

    public function testAbuseIpdbRequestBuildsExpectedUrlAndHeaders(): void
    {
        $req = abuseIpdbRequest('1.2.3.4', 'ABKEY');
        $this->assertSame('https://api.abuseipdb.com/api/v2/check?ipAddress=1.2.3.4&maxAgeInDays=90', $req['url']);
        $this->assertSame(['Key: ABKEY', 'Accept: application/json'], $req['headers']);
    }

    public function testShodanRequestBuildsExpectedUrl(): void
    {
        $req = shodanRequest('1.2.3.4', 'SHKEY');
        $this->assertSame('https://api.shodan.io/shodan/host/1.2.3.4?key=SHKEY&minify=true', $req['url']);
    }

    public function testPhishTankRequestBuildsExpectedPost(): void
    {
        $req = phishTankRequest('example.com', 'PTKEY');
        $this->assertSame('https://checkurl.phishtank.com/checkurl/', $req['url']);
        parse_str($req['post'], $fields);
        $this->assertSame('https://example.com', $fields['url']);
        $this->assertSame('json', $fields['format']);
        $this->assertSame('PTKEY', $fields['app_key']);
    }

    public function testUrlhausRequestBuildsExpectedPost(): void
    {
        $req = urlhausRequest('example.com');
        $this->assertSame('https://urlhaus-api.abuse.ch/v1/host/', $req['url']);
        parse_str($req['post'], $fields);
        $this->assertSame('example.com', $fields['host']);
    }

    public function testGeolocationRequestBuildsExpectedUrl(): void
    {
        $req = geolocationRequest('1.2.3.4');
        $this->assertSame('http://ip-api.com/json/1.2.3.4?fields=status,country,countryCode,region,city,isp,org,as', $req['url']);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Response parsers — parity against synthetic API responses
    // ═══════════════════════════════════════════════════════════════

    public function testParseSafeBrowsingResponseNoMatches(): void
    {
        $body = json_encode(['matches' => []]);
        $this->assertSame(['safe' => true, 'threats' => []], parseSafeBrowsingResponse(200, $body));
    }

    public function testParseSafeBrowsingResponseWithMatches(): void
    {
        $body = json_encode(['matches' => [['threatType' => 'MALWARE'], ['threatType' => 'MALWARE']]]);
        $result = parseSafeBrowsingResponse(200, $body);
        $this->assertFalse($result['safe']);
        $this->assertSame(['MALWARE'], array_values($result['threats']));
    }

    public function testParseSafeBrowsingResponseApiUnavailable(): void
    {
        $this->assertSame(
            ['safe' => true, 'threats' => [], 'error' => 'API unavailable'],
            parseSafeBrowsingResponse(500, null)
        );
        $this->assertSame(
            ['safe' => true, 'threats' => [], 'error' => 'API unavailable'],
            parseSafeBrowsingResponse(200, null)
        );
    }

    public function testParseVirusTotalResponseSuccess(): void
    {
        $body = json_encode([
            'data' => ['attributes' => [
                'last_analysis_stats' => ['malicious' => 2, 'suspicious' => 1, 'harmless' => 60, 'undetected' => 10],
                'reputation' => -5,
                'categories' => ['spam'],
            ]],
        ]);
        $this->assertSame(
            ['malicious' => 2, 'suspicious' => 1, 'harmless' => 60, 'undetected' => 10, 'reputation' => -5, 'categories' => ['spam']],
            parseVirusTotalResponse(200, $body)
        );
    }

    public function testParseVirusTotalResponseFailureCases(): void
    {
        $this->assertNull(parseVirusTotalResponse(404, null));
        $this->assertNull(parseVirusTotalResponse(200, json_encode(['data' => []])));
        $this->assertNull(parseVirusTotalResponse(200, null));
    }

    public function testParseAbuseIpdbResponseSuccess(): void
    {
        $body = json_encode(['data' => [
            'abuseConfidenceScore' => 42, 'totalReports' => 5, 'countryCode' => 'US',
            'isp' => 'Some ISP', 'isTor' => false, 'lastReportedAt' => '2026-01-01T00:00:00Z',
        ]]);
        $this->assertSame(
            ['abuse_score' => 42, 'total_reports' => 5, 'country_code' => 'US', 'isp' => 'Some ISP', 'is_tor' => false, 'last_reported' => '2026-01-01T00:00:00Z'],
            parseAbuseIpdbResponse(200, $body)
        );
    }

    public function testParseAbuseIpdbResponseFailureCases(): void
    {
        $this->assertNull(parseAbuseIpdbResponse(429, json_encode(['data' => []])));
        $this->assertNull(parseAbuseIpdbResponse(200, json_encode(['nope' => true])));
        $this->assertNull(parseAbuseIpdbResponse(200, null));
    }

    public function testParseShodanResponseSuccess(): void
    {
        $body = json_encode(['ports' => [443, 80], 'os' => 'Linux', 'org' => 'ExampleOrg', 'vulns' => ['CVE-1' => []], 'last_update' => '2026-01-01']);
        $result = parseShodanResponse(0, $body);
        $this->assertSame([80, 443], $result['ports']);
        $this->assertSame('Linux', $result['os']);
        $this->assertSame(['CVE-1'], $result['vulns']);
    }

    public function testParseShodanResponseErrorKeyMeansFailure(): void
    {
        // Shodan returns HTTP 200 with a body-level "error" key for e.g. "no
        // information available" — must still be treated as a failure
        // (matches the legacy httpFetch()-based implementation, which never
        // even looks at the HTTP status).
        $this->assertNull(parseShodanResponse(200, json_encode(['error' => 'No information available'])));
        $this->assertNull(parseShodanResponse(0, null));
    }

    public function testParsePhishTankResponseSuccess(): void
    {
        $body = json_encode(['results' => ['in_database' => true, 'valid' => true, 'verified' => true, 'phish_id' => 12345]]);
        $this->assertSame(
            ['in_database' => true, 'is_phish' => true, 'verified' => true, 'phish_id' => 12345],
            parsePhishTankResponse(0, $body)
        );
    }

    public function testParsePhishTankResponseFailureCases(): void
    {
        $this->assertNull(parsePhishTankResponse(0, json_encode(['nope' => true])));
        $this->assertNull(parsePhishTankResponse(0, null));
    }

    public function testParseUrlhausResponseSuccess(): void
    {
        $body = json_encode(['query_status' => 'ok', 'urls_online' => '3', 'blacklists' => ['x' => 'y'], 'tags' => range(1, 15)]);
        $result = parseUrlhausResponse(0, $body);
        $this->assertSame('ok', $result['status']);
        $this->assertSame(3, $result['urls_total']);
        $this->assertCount(10, $result['tags']); // sliced to 10, matches legacy
    }

    public function testParseUrlhausResponseFailureCases(): void
    {
        $this->assertNull(parseUrlhausResponse(0, json_encode('not-an-array')));
        $this->assertNull(parseUrlhausResponse(0, null));
    }

    public function testParseGeolocationResponseSuccess(): void
    {
        $body = json_encode(['status' => 'success', 'country' => 'United States', 'countryCode' => 'US', 'region' => 'CA', 'city' => 'X', 'isp' => 'Y', 'org' => 'Z', 'as' => 'AS1']);
        $this->assertSame(
            ['country' => 'United States', 'country_code' => 'US', 'region' => 'CA', 'city' => 'X', 'isp' => 'Y', 'org' => 'Z', 'as' => 'AS1'],
            parseGeolocationResponse(0, $body)
        );
    }

    public function testParseGeolocationResponseFailureCases(): void
    {
        $this->assertNull(parseGeolocationResponse(0, json_encode(['status' => 'fail'])));
        $this->assertNull(parseGeolocationResponse(0, null));
    }

    // ═══════════════════════════════════════════════════════════════
    //  runReputationModuleChecks() — gating parity, network-free
    //
    //  Every check in the 'reputation' registry has dnt=>true (hosting_risk
    //  is the sole exception, and it is unconditional/derived), so a DNT
    //  context skips ALL 7 network-issuing checks before Phase 2 (the
    //  curlMultiBatch()/serial-fallback branch) is ever reached — proving
    //  the gating logic without any network I/O.
    // ═══════════════════════════════════════════════════════════════

    public function testDntContextSkipsEveryNetworkCheckAndStillDerivesHostingRisk(): void
    {
        $ctx = [
            'domain' => 'example.com',
            'is_ip'  => false,
            // Irrelevant to this test — every check's dnt-gate is hit before
            // subject resolution (which is what 'dns' feeds) ever runs.
            'dns'    => [['type' => 'A', 'value' => '93.184.216.34']],
            'parsed' => [],
            'dnt'    => true,
            'config' => [
                'safe_browsing_api_key' => 'x', 'virustotal_api_key' => 'x', 'phishtank_api_key' => 'x',
                'abuseipdb_api_key' => 'x', 'shodan_api_key' => 'x',
            ],
        ];

        $result = runModuleChecks('reputation', $ctx);

        $this->assertSame(['hosting_risk' => null], $result['data']);
        $this->assertSame(
            [
                'safe_browsing' => 'dnt', 'virustotal' => 'dnt', 'phishtank' => 'dnt',
                'urlhaus' => 'dnt', 'abuseipdb' => 'dnt', 'shodan' => 'dnt', 'geolocation' => 'dnt',
            ],
            $result['skipped']
        );
    }

    public function testRunModuleChecksRoutesReputationThroughTheBatchedRunner(): void
    {
        // Confirms the wiring: runModuleChecks('reputation', ...) must be
        // byte-identical to calling runReputationModuleChecks() directly.
        $ctx = ['domain' => 'example.com', 'is_ip' => false, 'dns' => [], 'parsed' => [], 'dnt' => true, 'config' => []];
        $this->assertSame(runReputationModuleChecks($ctx), runModuleChecks('reputation', $ctx));
    }
}
