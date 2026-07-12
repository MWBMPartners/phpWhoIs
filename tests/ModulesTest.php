<?php

use PHPUnit\Framework\TestCase;

/**
 * Issue #196 Step 1 — module registry extraction.
 *
 * These tests are the Step 1 "gate": they prove moduleRegistry() /
 * runModuleChecks() reproduce the legacy inline enrichment pipeline's key set
 * and derived-value logic exactly, with no behaviour change.
 */
class ModulesTest extends TestCase
{
    // ═══════════════════════════════════════════════════════════════
    //  (a) Registry completeness — registry ∪ core-only ∪ security_score
    //      must equal the exact legacy enrichment key set.
    // ═══════════════════════════════════════════════════════════════

    /**
     * The exact set of enrichment-pipeline response keys the pre-refactor
     * lookup.php produced, extracted directly from the response array
     * literal (both the format=json and HTML branches carry the same set,
     * modulo raw vs whois which are core/transport keys, not enrichment).
     * Deliberately EXCLUDES the pure core/transport keys: domain, is_ip,
     * availability, data_source, parsed, dns, raw, whois, cached,
     * reverse_dns, verification_token, rate_limit, dnt — those were never
     * part of the "enrichment pipeline" gated by `if ($availability !==
     * 'available')` and are untouched by this refactor.
     */
    private function legacyEnrichmentKeys(): array
    {
        return [
            'email_security', 'ssl', 'geolocation', 'subdomains',
            'registrar_reputation', 'safe_browsing', 'virustotal',
            'screenshot_url', 'hibp', 'dnssec', 'cert_transparency',
            'domain_age_risk', 'abuseipdb', 'shodan', 'phishtank',
            'urlhaus', 'spamhaus', 'mta_sts', 'bimi', 'dane_tlsa',
            'whois_privacy', 'hosting_risk', 'http_headers',
            'redirect_chain', 'tls_audit', 'caa_records', 'smtp_security',
            'reverse_ip', 'http_versions', 'ipv6', 'response_times',
            'ns_diversity', 'domain_suggestions', 'tech_stack',
            'robots_txt', 'dns_propagation', 'multi_dnsbl',
        ];
    }

    /**
     * The "core" keys per the Issue #196 plan's module grouping — local or
     * derived-from-already-fetched-data computations that stay inline in
     * lookup.php (runCoreLookup() extraction is deferred past Step 1), so
     * they are NOT expected to appear in moduleRegistry().
     */
    private function coreOnlyKeys(): array
    {
        return [
            'registrar_reputation', 'domain_age_risk', 'whois_privacy',
            'screenshot_url', 'domain_suggestions',
        ];
    }

    private function allRegistryCheckKeys(): array
    {
        $keys = [];
        foreach (moduleRegistry() as $module => $checks) {
            foreach (array_keys($checks) as $checkKey) {
                $keys[] = $checkKey;
            }
        }
        return $keys;
    }

    public function testModuleRegistryOnlyContainsTheFiveGroupingModules(): void
    {
        $this->assertEqualsCanonicalizing(
            ['dns', 'web', 'email', 'reputation', 'subdomains'],
            array_keys(moduleRegistry()),
            'moduleRegistry() must contain exactly the 5 grouping modules — core and score are not registry modules.'
        );
    }

    public function testRegistryUnionCoreUnionScoreEqualsLegacyEnrichmentKeySet(): void
    {
        $registryKeys = $this->allRegistryCheckKeys();

        // No duplicate check-keys across modules.
        $this->assertCount(
            count($registryKeys),
            array_unique($registryKeys),
            'Every check-key must appear in exactly one module.'
        );

        $union = array_values(array_unique(array_merge(
            $registryKeys,
            $this->coreOnlyKeys(),
            ['security_score']
        )));

        $expected = array_values(array_unique(array_merge(
            $this->legacyEnrichmentKeys(),
            ['security_score']
        )));

        sort($union);
        sort($expected);

        $this->assertSame(
            $expected,
            $union,
            'registry-keys ∪ core-only-keys ∪ {security_score} must equal the legacy enrichment key set ∪ {security_score}.'
        );
    }

    public function testEveryDescriptorHasTheRequiredShape(): void
    {
        foreach (moduleRegistry() as $module => $checks) {
            foreach ($checks as $checkKey => $desc) {
                $this->assertArrayHasKey('fn', $desc, "$module.$checkKey missing 'fn'");
                $this->assertArrayHasKey('args', $desc, "$module.$checkKey missing 'args'");
                $this->assertArrayHasKey('dnt', $desc, "$module.$checkKey missing 'dnt'");
                $this->assertArrayHasKey('key', $desc, "$module.$checkKey missing 'key'");
                $this->assertArrayHasKey('domain_only', $desc, "$module.$checkKey missing 'domain_only'");
                $this->assertIsBool($desc['dnt'], "$module.$checkKey 'dnt' must be bool");
                $this->assertIsBool($desc['domain_only'], "$module.$checkKey 'domain_only' must be bool");
                $this->assertContains(
                    $desc['args'],
                    ['domain', 'first_a', 'first_a_or_ip', 'derived', 'special'],
                    "$module.$checkKey has an unrecognised 'args' value"
                );
                // Every real (non-derived, non-special) fn must be a callable
                // that actually exists in functions.php.
                if ($desc['fn'] !== null) {
                    $this->assertTrue(
                        function_exists($desc['fn']),
                        "$module.$checkKey references undefined function {$desc['fn']}()"
                    );
                }
            }
        }
    }

    // ═══════════════════════════════════════════════════════════════
    //  (b) deriveSpamhausFromMultiDnsbl() matches the old inline logic
    // ═══════════════════════════════════════════════════════════════

    public function testDeriveSpamhausWhenZenEntryListed(): void
    {
        $multiDnsbl = [
            'ip' => '1.2.3.4',
            'listed' => true,
            'total_checked' => 6,
            'lists' => [
                ['zone' => 'b.barracudacentral.org', 'label' => 'Barracuda'],
                ['zone' => 'zen.spamhaus.org', 'label' => 'Spamhaus ZEN'],
            ],
        ];

        $this->assertSame(
            ['listed' => true, 'lists' => [['zone' => 'zen.spamhaus.org', 'label' => 'Spamhaus ZEN']]],
            deriveSpamhausFromMultiDnsbl($multiDnsbl)
        );
    }

    public function testDeriveSpamhausWhenUnlisted(): void
    {
        $multiDnsbl = ['ip' => '1.2.3.4', 'listed' => false, 'total_checked' => 6, 'lists' => []];

        $this->assertSame(
            ['listed' => false, 'lists' => []],
            deriveSpamhausFromMultiDnsbl($multiDnsbl)
        );
    }

    public function testDeriveSpamhausWhenZenEntryAbsentButOthersListed(): void
    {
        // Listed on other DNSBLs but NOT on zen.spamhaus.org specifically —
        // the derived spamhaus.listed must be false (mirrors the legacy
        // "$zenEntry !== null" check, which only looks at the zen zone).
        $multiDnsbl = [
            'ip' => '1.2.3.4',
            'listed' => true,
            'total_checked' => 6,
            'lists' => [
                ['zone' => 'bl.spamcop.net', 'label' => 'SpamCop'],
            ],
        ];

        $this->assertSame(
            ['listed' => false, 'lists' => []],
            deriveSpamhausFromMultiDnsbl($multiDnsbl)
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  runModuleChecks() gating — exercised only with inputs that make
    //  every dispatched check short-circuit BEFORE any network/shell call,
    //  so these tests stay fast, deterministic, and offline.
    // ═══════════════════════════════════════════════════════════════

    public function testDnsAndWebModulesFullySkipForIpLookup(): void
    {
        $ctx = [
            'domain' => '203.0.113.5', // TEST-NET-3 (RFC 5737) — used as an opaque value only
            'is_ip'  => true,
            'dns'    => [],
            'parsed' => [],
            'dnt'    => false,
            'config' => [],
        ];

        foreach (['dns', 'web'] as $module) {
            $result = runModuleChecks($module, $ctx);
            $this->assertSame([], $result['data'], "$module module should produce no data for an IP lookup");
            $this->assertCount(
                count(moduleRegistry()[$module]),
                $result['skipped'],
                "$module module should record a skip reason for every registered check"
            );
        }
    }

    public function testReputationModuleFullySkipsUnderDntExceptHostingRisk(): void
    {
        $ctx = [
            'domain' => '203.0.113.5',
            'is_ip'  => true,
            'dns'    => [],
            'parsed' => [],
            'dnt'    => true,
            'config' => [],
        ];

        $result = runModuleChecks('reputation', $ctx);

        // hosting_risk is unconditional (legacy: assessHostingRisk() ran even
        // under DNT, using whatever geolocation resolved to — null here).
        $this->assertArrayHasKey('hosting_risk', $result['data']);
        $this->assertNull($result['data']['hosting_risk']);

        foreach (['safe_browsing', 'virustotal', 'phishtank', 'urlhaus', 'abuseipdb', 'shodan', 'geolocation'] as $key) {
            $this->assertArrayNotHasKey($key, $result['data'], "$key must not run under DNT");
            $this->assertArrayHasKey($key, $result['skipped'], "$key must be recorded as skipped under DNT");
        }
    }

    public function testEmailModuleDerivesSpamhausFromMultiDnsblViaRunModuleChecks(): void
    {
        // A non-IPv4 string makes checkMultiDnsbl() return immediately
        // (fails filter_var()'s FILTER_VALIDATE_IP check) with no DNS
        // queries, so this stays deterministic and offline while still
        // exercising the real multi_dnsbl -> spamhaus derivation path.
        $ctx = [
            'domain' => 'not-a-valid-ipv4',
            'is_ip'  => true,
            'dns'    => [],
            'parsed' => [],
            'dnt'    => true,
            'config' => [],
        ];

        $result = runModuleChecks('email', $ctx);

        foreach (['email_security', 'mta_sts', 'bimi', 'smtp_security', 'hibp'] as $key) {
            $this->assertArrayNotHasKey($key, $result['data'], "$key must be skipped for an IP lookup");
        }

        $this->assertSame(['listed' => false, 'lists' => []], $result['data']['multi_dnsbl']);
        $this->assertSame(['listed' => false, 'lists' => []], $result['data']['spamhaus']);
    }

    public function testUnknownModuleReturnsEmptyResult(): void
    {
        $result = runModuleChecks('not_a_real_module', [
            'domain' => 'example.com', 'is_ip' => false, 'dns' => [], 'parsed' => [], 'dnt' => false, 'config' => [],
        ]);
        $this->assertSame(['data' => [], 'skipped' => []], $result);
    }

    // ═══════════════════════════════════════════════════════════════
    //  Issue #196 Step 3 — per-module response cache
    // ═══════════════════════════════════════════════════════════════

    protected function tearDown(): void
    {
        // Module-cache tests below write real files under the test CACHE_DIR
        // (tests/bootstrap.php points it at a dedicated temp dir) — clean up
        // after each test so entries don't leak between test methods/runs.
        if (is_dir(CACHE_DIR)) {
            foreach (glob(CACHE_DIR . DIRECTORY_SEPARATOR . '*.json') ?: [] as $file) {
                @unlink($file);
            }
        }
    }

    public function testSetModuleCacheThenGetModuleCacheRoundTrips(): void
    {
        $payload = ['data' => ['dnssec' => ['signed' => true]], 'skipped' => []];
        setModuleCache('dns', 'example.com', false, $payload);

        $this->assertSame($payload, getModuleCache('dns', 'example.com', false));
    }

    public function testGetModuleCacheMissReturnsNull(): void
    {
        $this->assertNull(getModuleCache('web', 'never-cached-example.com', false));
    }

    public function testDnsModuleCacheIsSharedAcrossDntAndNonDnt(): void
    {
        // dns has no DNT-gated checks (moduleRegistry()'s 'dns' block: every
        // descriptor has 'dnt' => false), so its cache key must NOT carry a
        // :dnt suffix — a DNT caller and a non-DNT caller must hit the same
        // entry.
        $this->assertSame(
            moduleCacheKey('dns', 'example.com', false),
            moduleCacheKey('dns', 'example.com', true),
            'dns module cache key must be identical for dnt=true and dnt=false'
        );

        $payload = ['data' => ['ipv6' => ['ready' => false]], 'skipped' => []];
        setModuleCache('dns', 'example.com', false, $payload);

        $this->assertSame($payload, getModuleCache('dns', 'example.com', true));
    }

    public function testNonDnsModuleCacheKeysDivergeByDnt(): void
    {
        // Every other module (web/email/reputation/subdomains/core) has at
        // least one DNT-gated check, so dnt=true and dnt=false must be
        // cached separately to avoid ever serving a DNT-skipped payload to a
        // non-DNT caller (or vice versa).
        foreach (['web', 'email', 'reputation', 'subdomains', 'core'] as $module) {
            $this->assertNotSame(
                moduleCacheKey($module, 'example.com', false),
                moduleCacheKey($module, 'example.com', true),
                "$module module cache key must differ between dnt=true and dnt=false"
            );
        }

        $nonDnt = ['data' => ['ssl' => ['valid' => true]], 'skipped' => []];
        $dnt = ['data' => [], 'skipped' => ['http_headers' => 'dnt']];
        setModuleCache('web', 'example.com', false, $nonDnt);
        setModuleCache('web', 'example.com', true, $dnt);

        $this->assertSame($nonDnt, getModuleCache('web', 'example.com', false));
        $this->assertSame($dnt, getModuleCache('web', 'example.com', true));
    }

    public function testModuleCacheKeysAreNamespacedByModuleAndDomain(): void
    {
        $this->assertNotSame(
            moduleCacheKey('email', 'example.com', false),
            moduleCacheKey('web', 'example.com', false)
        );
        $this->assertNotSame(
            moduleCacheKey('email', 'example.com', false),
            moduleCacheKey('email', 'example.org', false)
        );
    }
}
