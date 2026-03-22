<?php

use PHPUnit\Framework\TestCase;

class LookupFunctionsTest extends TestCase
{
    // ═══════════════════════════════════════════════════════════════
    //  isValidDomain()
    // ═══════════════════════════════════════════════════════════════

    public function testValidDomains(): void
    {
        $this->assertTrue(isValidDomain('example.com'));
        $this->assertTrue(isValidDomain('bbc.co.uk'));
        $this->assertTrue(isValidDomain('sub.domain.example.org'));
        $this->assertTrue(isValidDomain('my-domain.net'));
        $this->assertTrue(isValidDomain('123.com'));
        $this->assertTrue(isValidDomain('a.io'));
    }

    public function testInvalidDomains(): void
    {
        $this->assertFalse(isValidDomain(''));
        $this->assertFalse(isValidDomain('example'));
        $this->assertFalse(isValidDomain('.com'));
        $this->assertFalse(isValidDomain('-example.com'));
        $this->assertFalse(isValidDomain('example-.com'));
        $this->assertFalse(isValidDomain('exam ple.com'));
        $this->assertFalse(isValidDomain('example.c'));
    }

    public function testShellDangerousCharactersRejected(): void
    {
        $this->assertFalse(isValidDomain('example.com;ls'));
        $this->assertFalse(isValidDomain('example.com|cat'));
        $this->assertFalse(isValidDomain('example.com&whoami'));
        $this->assertFalse(isValidDomain('example.com`id`'));
        $this->assertFalse(isValidDomain('$(evil).com'));
        $this->assertFalse(isValidDomain("example.com'"));
        $this->assertFalse(isValidDomain('example.com"'));
    }

    public function testExcessivelyLongDomainRejected(): void
    {
        $longDomain = str_repeat('a', 250) . '.com';
        $this->assertFalse(isValidDomain($longDomain));
    }


    // ═══════════════════════════════════════════════════════════════
    //  sanitizeDomainInput()
    // ═══════════════════════════════════════════════════════════════

    public function testSanitizesUrls(): void
    {
        $this->assertEquals('example.com', sanitizeDomainInput('https://www.example.com/page'));
        $this->assertEquals('example.com', sanitizeDomainInput('http://example.com'));
        $this->assertEquals('example.com', sanitizeDomainInput('https://example.com/path?query=1'));
    }

    public function testSanitizesWwwPrefix(): void
    {
        $this->assertEquals('example.com', sanitizeDomainInput('www.example.com'));
        $this->assertEquals('example.com', sanitizeDomainInput('WWW.example.com'));
    }

    public function testSanitizesBareDomains(): void
    {
        $this->assertEquals('example.com', sanitizeDomainInput('example.com'));
        $this->assertEquals('example.com', sanitizeDomainInput('  example.com  '));
    }

    public function testStripsNullBytes(): void
    {
        $this->assertEquals('example.com', sanitizeDomainInput("example\0.com"));
    }

    public function testRejectsOversizedInput(): void
    {
        $longInput = str_repeat('a', 300) . '.com';
        $this->assertEquals('', sanitizeDomainInput($longInput));
    }


    // ═══════════════════════════════════════════════════════════════
    //  extractRegistrableDomain()
    // ═══════════════════════════════════════════════════════════════

    public function testExtractsSimpleDomain(): void
    {
        $this->assertEquals('example.com', extractRegistrableDomain('example.com'));
        $this->assertEquals('example.org', extractRegistrableDomain('sub.example.org'));
    }

    public function testExtractsSinglePartInput(): void
    {
        // Single part should return as-is (unusual case)
        $this->assertEquals('localhost', extractRegistrableDomain('localhost'));
    }


    // ═══════════════════════════════════════════════════════════════
    //  detectAvailability()
    // ═══════════════════════════════════════════════════════════════

    public function testDetectsRegisteredDomain(): void
    {
        $whois = "Domain Name: EXAMPLE.COM\nRegistrar: Example Registrar\nCreation Date: 1995-08-14";
        $this->assertEquals('registered', detectAvailability($whois));
    }

    public function testDetectsRegisteredByRegistryId(): void
    {
        $whois = "Registry Domain ID: 12345_DOMAIN_COM-VRSN\nDomain Name: EXAMPLE.COM";
        $this->assertEquals('registered', detectAvailability($whois));
    }

    public function testDetectsAvailableNoMatch(): void
    {
        $whois = "No match for domain \"NOTEXIST123456.COM\".";
        $this->assertEquals('available', detectAvailability($whois));
    }

    public function testDetectsAvailableNotFound(): void
    {
        $whois = "NOT FOUND";
        $this->assertEquals('available', detectAvailability($whois));
    }

    public function testDetectsAvailableStatusFree(): void
    {
        $whois = "Status: free";
        $this->assertEquals('available', detectAvailability($whois));
    }

    public function testRegistrationIndicatorsTakePriority(): void
    {
        // Even if "No match" appears in boilerplate, registration fields should win
        $whois = "Registrar: Example\nCreation Date: 2020-01-01\nTerms of use: No match for unauthorised use.";
        $this->assertEquals('registered', detectAvailability($whois));
    }

    public function testAvailablePatternsMustBeLineAnchored(): void
    {
        // "available" or "no match" appearing mid-sentence in boilerplate should NOT trigger
        $whois = "Registrar: Example\nThis data is available for information purposes only.";
        $this->assertEquals('registered', detectAvailability($whois));
    }


    // ═══════════════════════════════════════════════════════════════
    //  parseWhoisFields()
    // ═══════════════════════════════════════════════════════════════

    public function testParsesBasicWhoisFields(): void
    {
        $whois = implode("\n", [
            "Domain Name: EXAMPLE.COM",
            "Registrar: Test Registrar Inc.",
            "Creation Date: 2020-01-15T00:00:00Z",
            "Expiry Date: 2025-01-15T00:00:00Z",
            "Updated Date: 2024-06-01T00:00:00Z",
            "Registrant Organization: Example Corp",
            "Registrant Country: US",
        ]);

        $fields = parseWhoisFields($whois);

        $this->assertEquals('EXAMPLE.COM', $fields['Domain Name']);
        $this->assertEquals('Test Registrar Inc.', $fields['Registrar']);
        $this->assertEquals('2020-01-15T00:00:00Z', $fields['Creation Date']);
        $this->assertEquals('2025-01-15T00:00:00Z', $fields['Expiry Date']);
        $this->assertEquals('2024-06-01T00:00:00Z', $fields['Updated Date']);
        $this->assertEquals('Example Corp', $fields['Registrant Org']);
        $this->assertEquals('US', $fields['Registrant Country']);
    }

    public function testParsesMultipleStatuses(): void
    {
        $whois = "Domain Status: clientTransferProhibited\nDomain Status: serverDeleteProhibited";
        $fields = parseWhoisFields($whois);

        $this->assertCount(2, $fields['Status']);
        $this->assertContains('clientTransferProhibited', $fields['Status']);
        $this->assertContains('serverDeleteProhibited', $fields['Status']);
    }

    public function testParsesNameServers(): void
    {
        $whois = "Name Server: NS1.EXAMPLE.COM\nName Server: NS2.EXAMPLE.COM";
        $fields = parseWhoisFields($whois);

        $this->assertCount(2, $fields['Name Servers']);
        $this->assertContains('NS1.EXAMPLE.COM', $fields['Name Servers']);
    }

    public function testCalculatesDomainAge(): void
    {
        $whois = "Creation Date: 2020-01-01T00:00:00Z";
        $fields = parseWhoisFields($whois);

        $this->assertArrayHasKey('Domain Age', $fields);
        $this->assertStringContainsString('year', $fields['Domain Age']);
    }

    public function testCalculatesExpiryCountdown(): void
    {
        $futureDate = date('Y-m-d\TH:i:s\Z', strtotime('+100 days'));
        $whois = "Expiry Date: " . $futureDate;
        $fields = parseWhoisFields($whois);

        $this->assertArrayHasKey('Expires In', $fields);
        $this->assertStringContainsString('days', $fields['Expires In']);
    }

    public function testHandlesEmptyWhois(): void
    {
        $fields = parseWhoisFields('');
        $this->assertEmpty($fields);
    }


    // ═══════════════════════════════════════════════════════════════
    //  extractSecondLevelSuffixes()
    // ═══════════════════════════════════════════════════════════════

    public function testExtractsSuffixesFromPsl(): void
    {
        $psl = implode("\n", [
            "// Some comment",
            "// ===BEGIN ICANN DOMAINS===",
            "com",
            "co.uk",
            "org.uk",
            "net",
            "*.ck",
            "!www.ck",
            "// ===END ICANN DOMAINS===",
            "// ===BEGIN PRIVATE DOMAINS===",
            "github.io",
        ]);

        $suffixes = extractSecondLevelSuffixes($psl);

        $this->assertContains('co.uk', $suffixes);
        $this->assertContains('org.uk', $suffixes);
        // Single TLDs should NOT be included
        $this->assertNotContains('com', $suffixes);
        $this->assertNotContains('net', $suffixes);
        // Wildcards and negations should NOT be included
        $this->assertNotContains('*.ck', $suffixes);
        $this->assertNotContains('!www.ck', $suffixes);
        // Private domains should NOT be included
        $this->assertNotContains('github.io', $suffixes);
    }


    // ═══════════════════════════════════════════════════════════════
    //  formatRdapResponse()
    // ═══════════════════════════════════════════════════════════════

    public function testFormatsBasicRdapResponse(): void
    {
        $rdap = [
            'ldhName' => 'example.com',
            'status' => ['active'],
            'events' => [
                ['eventAction' => 'registration', 'eventDate' => '2020-01-01T00:00:00Z'],
            ],
            'nameservers' => [
                ['ldhName' => 'ns1.example.com'],
                ['ldhName' => 'ns2.example.com'],
            ],
        ];

        $result = formatRdapResponse($rdap);

        $this->assertStringContainsString('EXAMPLE.COM', $result);
        $this->assertStringContainsString('active', $result);
        $this->assertStringContainsString('Registration', $result);
        $this->assertStringContainsString('ns1.example.com', $result);
        $this->assertStringContainsString('ns2.example.com', $result);
    }

    public function testFormatsEmptyRdapResponse(): void
    {
        $result = formatRdapResponse([]);
        $this->assertEquals('', $result);
    }


    // ═══════════════════════════════════════════════════════════════
    //  Caching
    // ═══════════════════════════════════════════════════════════════

    public function testCacheSetAndGet(): void
    {
        $domain = 'test-cache-' . time() . '.com';
        $data = 'Test WHOIS data';

        setCache($domain, $data);
        $cached = getCached($domain);

        $this->assertEquals($data, $cached);

        // Clean up
        $file = CACHE_DIR . DIRECTORY_SEPARATOR . md5($domain) . '.json';
        if (file_exists($file)) {
            unlink($file);
        }
    }

    public function testCacheMissReturnsNull(): void
    {
        $this->assertNull(getCached('nonexistent-domain-' . time() . '.com'));
    }
}
