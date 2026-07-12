<?php

use PHPUnit\Framework\TestCase;

/**
 * Issue #196 Step 4 — the lookup_token HMAC.
 *
 * A `modules=core` response issues one of these so the frontend's follow-up
 * module-tab fetches for the same domain are exempt from rate-limit
 * counting. validateLookupToken() must return false — never throw — for
 * EVERY failure mode (expired, wrong domain, wrong binding, tampered HMAC,
 * or a malformed/garbage token), so a bad token always degrades to normal
 * counted rate limiting rather than ever causing a hard error.
 */
class LookupTokenTest extends TestCase
{
    protected function tearDown(): void
    {
        // moduleTokenSecret() persists its key under CACHE_DIR (tests/
        // bootstrap.php points this at a dedicated temp dir) — clean up so
        // it doesn't leak between test runs/methods.
        $path = CACHE_DIR . DIRECTORY_SEPARATOR . '.module_token_key';
        @unlink($path);
        @unlink($path . '.lock');
    }

    // ═══════════════════════════════════════════════════════════════
    //  moduleTokenSecret()
    // ═══════════════════════════════════════════════════════════════

    public function testModuleTokenSecretIs32BytesAndStable(): void
    {
        $a = moduleTokenSecret();
        $b = moduleTokenSecret();

        $this->assertSame(32, strlen($a), 'secret must be exactly 32 random bytes');
        $this->assertSame($a, $b, 'repeated calls within the same process must return the same secret');
    }

    public function testModuleTokenSecretPersistsAcrossFreshReadsOfTheFile(): void
    {
        $secret = moduleTokenSecret();
        $path = CACHE_DIR . DIRECTORY_SEPARATOR . '.module_token_key';

        $this->assertFileExists($path);
        $this->assertSame($secret, file_get_contents($path));

        // A brand-new "process" (no static cache) reading the same file
        // must derive the exact same secret — this is what lets a token
        // issued by one request validate correctly on the next.
        $onDisk = file_get_contents($path);
        $this->assertSame(32, strlen($onDisk));
    }

    public function testModuleTokenSecretFileIsNotWorldOrGroupReadable(): void
    {
        moduleTokenSecret();
        $path = CACHE_DIR . DIRECTORY_SEPARATOR . '.module_token_key';
        $perms = fileperms($path) & 0777;

        $this->assertSame(0600, $perms, 'secret key file must be chmod 0600');
    }

    // ═══════════════════════════════════════════════════════════════
    //  issueLookupToken() / validateLookupToken() — happy path
    // ═══════════════════════════════════════════════════════════════

    public function testValidTokenRoundTrips(): void
    {
        $token = issueLookupToken('example.com', 'binding-a');

        $this->assertTrue(validateLookupToken($token, 'example.com', 'binding-a'));
    }

    public function testTokenHasTheExpectedTwoPartShape(): void
    {
        $token = issueLookupToken('example.com', 'binding-a');

        $this->assertSame(1, substr_count($token, '.'), 'token must be exactly payload.signature');
        [$payloadB64, $sigB64] = explode('.', $token, 2);
        $this->assertNotSame('', $payloadB64);
        $this->assertNotSame('', $sigB64);

        $payload = json_decode(base64UrlDecode($payloadB64), true);
        $this->assertIsArray($payload);
        $this->assertSame(1, $payload['v']);
        $this->assertSame('example.com', $payload['d']);
        $this->assertSame('binding-a', $payload['b']);
        $this->assertArrayHasKey('exp', $payload);
        $this->assertArrayHasKey('n', $payload);
        $this->assertGreaterThan(time(), $payload['exp']);
        $this->assertLessThanOrEqual(time() + 180, $payload['exp']);
    }

    public function testTwoIssuedTokensForTheSameInputsAreNotIdentical(): void
    {
        // The random nonce ('n') must make each issuance unique even for the
        // exact same domain/binding issued in the same second.
        $a = issueLookupToken('example.com', 'binding-a');
        $b = issueLookupToken('example.com', 'binding-a');

        $this->assertNotSame($a, $b);
        // But both must still independently validate.
        $this->assertTrue(validateLookupToken($a, 'example.com', 'binding-a'));
        $this->assertTrue(validateLookupToken($b, 'example.com', 'binding-a'));
    }

    // ═══════════════════════════════════════════════════════════════
    //  validateLookupToken() — every failure mode must return false,
    //  never throw
    // ═══════════════════════════════════════════════════════════════

    public function testExpiredTokenIsRejected(): void
    {
        // Forge a payload with exp in the past, signed with the real secret,
        // exactly mirroring issueLookupToken()'s own encoding.
        $payload = ['v' => 1, 'd' => 'example.com', 'b' => 'binding-a', 'exp' => time() - 10, 'n' => 'aaaa'];
        $payloadB64 = base64UrlEncode(json_encode($payload));
        $sig = hash_hmac('sha256', $payloadB64, moduleTokenSecret(), true);
        $token = $payloadB64 . '.' . base64UrlEncode($sig);

        $this->assertFalse(validateLookupToken($token, 'example.com', 'binding-a'));
    }

    public function testWrongDomainIsRejected(): void
    {
        $token = issueLookupToken('example.com', 'binding-a');

        $this->assertFalse(validateLookupToken($token, 'not-example.com', 'binding-a'));
    }

    public function testWrongBindingIsRejected(): void
    {
        $token = issueLookupToken('example.com', 'binding-a');

        $this->assertFalse(validateLookupToken($token, 'example.com', 'binding-b'));
    }

    public function testTamperedPayloadFailsHmacCheck(): void
    {
        $token = issueLookupToken('example.com', 'binding-a');
        [$payloadB64, $sigB64] = explode('.', $token, 2);

        // Swap in a payload claiming a different domain, but keep the
        // ORIGINAL signature — the HMAC no longer matches the new payload.
        $forgedPayload = base64UrlEncode(json_encode(['v' => 1, 'd' => 'evil.com', 'b' => 'binding-a', 'exp' => time() + 180, 'n' => 'aaaa']));
        $forgedToken = $forgedPayload . '.' . $sigB64;

        $this->assertFalse(validateLookupToken($forgedToken, 'evil.com', 'binding-a'));
    }

    public function testTamperedSignatureIsRejected(): void
    {
        $token = issueLookupToken('example.com', 'binding-a');
        [$payloadB64, $sigB64] = explode('.', $token, 2);

        // Flip the last character of the signature.
        $lastChar = substr($sigB64, -1);
        $flipped = ($lastChar === 'A') ? 'B' : 'A';
        $tamperedSig = substr($sigB64, 0, -1) . $flipped;
        $tamperedToken = $payloadB64 . '.' . $tamperedSig;

        $this->assertFalse(validateLookupToken($tamperedToken, 'example.com', 'binding-a'));
    }

    public function testTokenSignedWithADifferentSecretIsRejected(): void
    {
        $payload = ['v' => 1, 'd' => 'example.com', 'b' => 'binding-a', 'exp' => time() + 180, 'n' => 'aaaa'];
        $payloadB64 = base64UrlEncode(json_encode($payload));
        $sig = hash_hmac('sha256', $payloadB64, 'a-completely-different-secret-not-from-disk', true);
        $token = $payloadB64 . '.' . base64UrlEncode($sig);

        $this->assertFalse(validateLookupToken($token, 'example.com', 'binding-a'));
    }

    /**
     * @dataProvider malformedTokenProvider
     */
    public function testMalformedTokensAreRejectedWithoutThrowing(string $token): void
    {
        $this->assertFalse(validateLookupToken($token, 'example.com', 'binding-a'));
    }

    public static function malformedTokenProvider(): array
    {
        return [
            'empty string' => [''],
            'no dot separator' => ['not-a-token-at-all'],
            'too many dots' => ['a.b.c'],
            'empty payload segment' => ['.abc123'],
            'empty signature segment' => ['abc123.'],
            'invalid base64 payload' => ['!!!not-base64!!!.dGVzdA'],
            'invalid base64 signature' => ['dGVzdA.!!!not-base64!!!'],
            'valid base64 but not JSON payload' => [base64UrlEncode('not json at all') . '.' . base64UrlEncode('irrelevant-signature-bytes')],
            'JSON array instead of object' => [base64UrlEncode(json_encode([1, 2, 3])) . '.' . base64UrlEncode('sig')],
            'JSON scalar payload' => [base64UrlEncode(json_encode('just a string')) . '.' . base64UrlEncode('sig')],
        ];
    }

    public function testMalformedJsonMissingRequiredFieldsIsRejected(): void
    {
        // Sign a well-formed-but-incomplete payload with the REAL secret so
        // this specifically exercises the post-HMAC field-validation path,
        // not just "HMAC mismatch".
        foreach (['v', 'd', 'b', 'exp'] as $omit) {
            $payload = ['v' => 1, 'd' => 'example.com', 'b' => 'binding-a', 'exp' => time() + 180, 'n' => 'aaaa'];
            unset($payload[$omit]);
            $payloadB64 = base64UrlEncode(json_encode($payload));
            $sig = hash_hmac('sha256', $payloadB64, moduleTokenSecret(), true);
            $token = $payloadB64 . '.' . base64UrlEncode($sig);

            $this->assertFalse(
                validateLookupToken($token, 'example.com', 'binding-a'),
                "token missing '$omit' must be rejected"
            );
        }
    }

    public function testWrongVersionIsRejected(): void
    {
        $payload = ['v' => 2, 'd' => 'example.com', 'b' => 'binding-a', 'exp' => time() + 180, 'n' => 'aaaa'];
        $payloadB64 = base64UrlEncode(json_encode($payload));
        $sig = hash_hmac('sha256', $payloadB64, moduleTokenSecret(), true);
        $token = $payloadB64 . '.' . base64UrlEncode($sig);

        $this->assertFalse(validateLookupToken($token, 'example.com', 'binding-a'));
    }

    public function testNonStringDomainOrBindingFieldsAreRejected(): void
    {
        // 'd' as an array instead of a string — must be rejected cleanly
        // rather than causing a type error on the `!==` comparison.
        $payload = ['v' => 1, 'd' => ['example.com'], 'b' => 'binding-a', 'exp' => time() + 180, 'n' => 'aaaa'];
        $payloadB64 = base64UrlEncode(json_encode($payload));
        $sig = hash_hmac('sha256', $payloadB64, moduleTokenSecret(), true);
        $token = $payloadB64 . '.' . base64UrlEncode($sig);

        $this->assertFalse(validateLookupToken($token, 'example.com', 'binding-a'));
    }

    // ═══════════════════════════════════════════════════════════════
    //  resolveLookupTokenBinding()
    // ═══════════════════════════════════════════════════════════════

    public function testBindingDiffersBetweenApiKeyAndSessionCallers(): void
    {
        $sessionBinding = resolveLookupTokenBinding(null, '');
        $apiKeyBinding = resolveLookupTokenBinding(['tier' => 'free'], 'some-raw-api-key');

        $this->assertNotSame($sessionBinding, $apiKeyBinding);
    }

    public function testBindingIsStableForTheSameApiKey(): void
    {
        $a = resolveLookupTokenBinding(['tier' => 'free'], 'same-key');
        $b = resolveLookupTokenBinding(['tier' => 'free'], 'same-key');

        $this->assertSame($a, $b);
    }

    public function testBindingDiffersForDifferentApiKeys(): void
    {
        $a = resolveLookupTokenBinding(['tier' => 'free'], 'key-one');
        $b = resolveLookupTokenBinding(['tier' => 'free'], 'key-two');

        $this->assertNotSame($a, $b);
    }

    public function testApiKeyConfigWithEmptyHeaderFallsBackToSessionBinding(): void
    {
        // Defensive edge case: $apiKeyConfig set but the raw header string
        // is somehow empty — must not produce hash('sha256', hash('sha256', ''))
        // silently; falls back to the session_id()-based binding instead.
        $this->assertSame(
            resolveLookupTokenBinding(null, ''),
            resolveLookupTokenBinding(['tier' => 'free'], '')
        );
    }

    // ═══════════════════════════════════════════════════════════════
    //  base64UrlEncode()/base64UrlDecode()
    // ═══════════════════════════════════════════════════════════════

    public function testBase64UrlRoundTripsArbitraryBytes(): void
    {
        $bytes = random_bytes(64);
        $this->assertSame($bytes, base64UrlDecode(base64UrlEncode($bytes)));
    }

    public function testBase64UrlEncodeOutputHasNoPaddingOrUnsafeChars(): void
    {
        $encoded = base64UrlEncode(random_bytes(37)); // odd length forces padding in std base64
        $this->assertStringNotContainsString('=', $encoded);
        $this->assertStringNotContainsString('+', $encoded);
        $this->assertStringNotContainsString('/', $encoded);
    }
}
