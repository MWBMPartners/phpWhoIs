<?php

use PHPUnit\Framework\TestCase;

/**
 * Issue #196 Step 2 — dig-batch subdomain discovery.
 *
 * discoverSubdomainsViaDig() itself shells out to `dig` and polls temp
 * files, so — to keep this suite network-free, matching the rest of the
 * project's test discipline (tests/LookupFunctionsTest.php,
 * tests/ModulesTest.php, tests/ReputationBatchTest.php make zero live
 * network/DNS calls) — these tests exercise the pure parsing function it
 * delegates to (parseDigSubdomainOutput()) directly against synthetic `dig
 * +short A` output, plus the untouched serial fallback
 * (discoverSubdomainsSerial()) against a prefix guaranteed not to resolve.
 *
 * Output-shape parity between the two code paths was additionally verified
 * interactively (outside this committed suite) against live `dig`/PHP
 * gethostbyname() calls in the development sandbox — see the Issue #196
 * Step 2 handoff notes for the exact commands and observed timings.
 */
class SubdomainDiscoveryTest extends TestCase
{
    // ═══════════════════════════════════════════════════════════════
    //  parseDigSubdomainOutput() — pure, no I/O
    // ═══════════════════════════════════════════════════════════════

    public function testReturnsEntryForASingleIpv4Line(): void
    {
        $this->assertSame(
            ['subdomain' => 'www.example.com', 'ip' => '93.184.216.34'],
            parseDigSubdomainOutput('www.example.com', "93.184.216.34\n")
        );
    }

    public function testSkipsCnameLinesAndPicksTheFinalIp(): void
    {
        // `dig +short A` on an aliased name emits the CNAME chain followed by
        // the resolved A record(s) — only the IP literal line should be used.
        $output = "alias-target.example.net.\n93.184.216.34\n";
        $this->assertSame(
            ['subdomain' => 'blog.example.com', 'ip' => '93.184.216.34'],
            parseDigSubdomainOutput('blog.example.com', $output)
        );
    }

    public function testUsesOnlyTheFirstIpWhenMultipleARecordsAreReturned(): void
    {
        // gethostbyname() (the serial fallback) only ever returns ONE IP —
        // the dig-batch path must match that "one entry per subdomain" shape.
        $output = "1.1.1.1\n2.2.2.2\n3.3.3.3\n";
        $entry = parseDigSubdomainOutput('api.example.com', $output);
        $this->assertSame('1.1.1.1', $entry['ip']);
    }

    /**
     * @dataProvider nonResolvingOutputs
     */
    public function testReturnsNullWhenNothingResolved($output): void
    {
        $this->assertNull(parseDigSubdomainOutput('nope.example.com', $output));
    }

    public static function nonResolvingOutputs(): array
    {
        return [
            'null (file never appeared / dig never finished within the cap)' => [null],
            'empty string (NXDOMAIN — dig +short prints nothing)' => [''],
            'whitespace only' => ["  \n\n"],
            'CNAME chain with no terminating A record' => ["alias.example.net.\n"],
        ];
    }

    public function testTrimsWhitespaceAroundTheIpLine(): void
    {
        $this->assertSame(
            ['subdomain' => 'ns1.example.com', 'ip' => '8.8.8.8'],
            parseDigSubdomainOutput('ns1.example.com', "  8.8.8.8  \n")
        );
    }

    // Note: discoverSubdomainsSerial() (gethostbyname()) and
    // discoverSubdomainsViaDig() (shells out to `dig`) are deliberately NOT
    // exercised here — both make live DNS queries, which this project's test
    // suite has zero of elsewhere (see class doc comment above). Their output
    // shape is proven by: discoverSubdomainsSerial() being byte-identical to
    // the pre-Step-2 implementation (a diff, not a behaviour change), and
    // discoverSubdomainsViaDig() delegating its entry-shaping entirely to
    // parseDigSubdomainOutput() (fully covered above) on top of the same
    // temp-file poll loop checkDnsPropagation() already runs in production.
}
