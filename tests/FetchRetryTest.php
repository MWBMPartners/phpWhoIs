<?php

use PHPUnit\Framework\TestCase;

// The helper lives outside web/ so tests/bootstrap.php does not load it.
require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'scripts'
    . DIRECTORY_SEPARATOR . 'lib' . DIRECTORY_SEPARATOR . 'fetch.php';

/**
 * Unit tests for the resilient fetch helper (scripts/lib/fetch.php).
 *
 * Every test injects a fake transport + a capturing sleeper + a silent logger,
 * so nothing touches the network and nothing actually sleeps.
 */
class FetchRetryTest extends TestCase
{
    /** @var int[] Milliseconds passed to the injected sleeper, in order. */
    private array $delays = [];

    /** A sleeper that records requested delays instead of sleeping. */
    private function recordingSleeper(): callable
    {
        $this->delays = [];
        return function (int $ms): void { $this->delays[] = $ms; };
    }

    /** A logger that swallows output. */
    private function nullLogger(): callable
    {
        return function (string $line): void { /* no-op */ };
    }

    /**
     * Build a transport that returns the given canned responses in sequence.
     * Each response is [body, httpCode, error].
     */
    private function scriptedTransport(array $responses): callable
    {
        $i = 0;
        return function (string $url, array $opts) use (&$i, $responses): array {
            $r = $responses[min($i, count($responses) - 1)];
            $i++;
            return ['body' => $r[0], 'httpCode' => $r[1], 'error' => $r[2] ?? ''];
        };
    }

    private function ok(int $bytes = 200): array
    {
        return [str_repeat('x', $bytes), 200, ''];
    }

    public function testSucceedsOnFirstAttempt(): void
    {
        $res = fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 1],
            $this->scriptedTransport([$this->ok()]),
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        $this->assertTrue($res['ok']);
        $this->assertSame(1, $res['attempts']);
        $this->assertSame(200, $res['httpCode']);
        $this->assertCount(0, $this->delays, 'no backoff should occur on first-try success');
    }

    public function testRetriesAfterTimeoutThenSucceeds(): void
    {
        $res = fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 1],
            $this->scriptedTransport([
                [null, 0, 'Operation timed out'],
                [null, 0, 'Operation timed out'],
                $this->ok(),
            ]),
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        $this->assertTrue($res['ok']);
        $this->assertSame(3, $res['attempts']);
        $this->assertCount(2, $this->delays, 'two backoffs before the third, successful attempt');
    }

    public function testBackoffDelaysGrowWithinJitterBounds(): void
    {
        fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 1, 'baseDelay' => 2],
            $this->scriptedTransport([
                [null, 0, 'timeout'],
                [null, 0, 'timeout'],
                $this->ok(),
            ]),
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        // baseDelay 2s → 2000ms and 4000ms, each + 0–1000ms full jitter.
        $this->assertGreaterThanOrEqual(2000, $this->delays[0]);
        $this->assertLessThanOrEqual(3000, $this->delays[0]);
        $this->assertGreaterThanOrEqual(4000, $this->delays[1]);
        $this->assertLessThanOrEqual(5000, $this->delays[1]);
    }

    public function testAllAttemptsFailReturnsSoftFailure(): void
    {
        $res = fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 1, 'attempts' => 4],
            $this->scriptedTransport([[null, 0, 'Operation timed out']]),
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        $this->assertFalse($res['ok']);
        $this->assertSame(4, $res['attempts']);
        $this->assertNull($res['body']);
        $this->assertStringContainsString('timed out', $res['error']);
        $this->assertCount(3, $this->delays, 'three backoffs between four attempts');
    }

    public function testNonRetryable404StopsImmediately(): void
    {
        $res = fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 1],
            $this->scriptedTransport([['not found', 404, '']]),
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        $this->assertFalse($res['ok']);
        $this->assertSame(1, $res['attempts']);
        $this->assertCount(0, $this->delays, '4xx is permanent — no retries');
    }

    public function testRetriesOn503(): void
    {
        $res = fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 1],
            $this->scriptedTransport([
                ['service unavailable', 503, ''],
                $this->ok(),
            ]),
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        $this->assertTrue($res['ok']);
        $this->assertSame(2, $res['attempts']);
    }

    public function testTinyBodyTreatedAsRetryableFailure(): void
    {
        $res = fetchUrlWithRetry(
            'https://example.test/data',
            ['minBytes' => 100, 'attempts' => 4],
            $this->scriptedTransport([['x', 200, '']]),   // 1 byte, always
            $this->recordingSleeper(),
            $this->nullLogger()
        );

        $this->assertFalse($res['ok']);
        $this->assertSame(4, $res['attempts']);
        $this->assertStringContainsString('body too small', $res['error']);
        $this->assertCount(3, $this->delays);
    }

    public function testIsRetryableHttpFailureMatrix(): void
    {
        $this->assertTrue(isRetryableHttpFailure(0));     // transport error
        $this->assertTrue(isRetryableHttpFailure(408));
        $this->assertTrue(isRetryableHttpFailure(429));
        $this->assertTrue(isRetryableHttpFailure(500));
        $this->assertTrue(isRetryableHttpFailure(503));
        $this->assertFalse(isRetryableHttpFailure(403));
        $this->assertFalse(isRetryableHttpFailure(404));
        $this->assertFalse(isRetryableHttpFailure(410));
    }
}
