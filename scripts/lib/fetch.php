<?php
/**
 * Resilient HTTP fetch helper (retry + exponential backoff + jitter).
 *
 * Used by CI maintenance scripts (e.g. scripts/update-dns-resolvers.php) that
 * pull data from third-party endpoints which are occasionally slow or briefly
 * unavailable. A single un-retried request there turns a whole daily job red on
 * a transient upstream hiccup — this helper makes the fetch tolerant instead.
 *
 * Design:
 *   - cURL is preferred (hard total-time cap, separate connect timeout, gzip,
 *     HTTP status + error strings for diagnosability). It is the codebase's own
 *     idiom (see includes/functions.php rdapLookup()).
 *   - A PHP streams fallback keeps the helper working on curl-less hosts, so the
 *     fix is never a capability regression.
 *   - Transport, sleeper and logger are injectable so the retry logic can be
 *     unit-tested with no network and no real sleeping (see tests/FetchRetryTest.php).
 *
 * PHP 7.4+, no external dependencies.
 */

/**
 * Which failures are worth retrying?
 * Transport errors (httpCode 0 — timeout / DNS / TLS / connection reset), plus
 * 408, 429 and any 5xx. Other 4xx (403/404/410 …) are permanent — fail fast.
 *
 * @param int    $httpCode HTTP status, or 0 for a transport-level failure.
 * @param string $error    Transport error string (unused in the decision today,
 *                         kept so callers/log lines carry the reason).
 */
function isRetryableHttpFailure(int $httpCode, string $error = ''): bool
{
    if ($httpCode === 0)   return true;   // timeout, DNS, TLS, connection reset
    if ($httpCode === 408) return true;   // request timeout
    if ($httpCode === 429) return true;   // rate limited
    if ($httpCode >= 500)  return true;   // upstream server error
    return false;
}

/**
 * Perform a single GET.
 *
 * @return array{body: ?string, httpCode: int, error: string}
 *         httpCode 0 signals a transport-level failure (nothing received).
 */
function defaultHttpTransport(string $url, array $options): array
{
    $connectTimeout = (int)($options['connectTimeout'] ?? 10);
    $timeout        = (int)($options['timeout'] ?? 60);
    $userAgent      = (string)($options['userAgent'] ?? 'mwWhoIs/1.0');

    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_CONNECTTIMEOUT => $connectTimeout,
            CURLOPT_TIMEOUT        => $timeout,   // hard total wall-clock cap
            CURLOPT_USERAGENT      => $userAgent,
            CURLOPT_ENCODING       => '',         // advertise gzip/deflate, auto-decompress
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            CURLOPT_NOSIGNAL       => 1,
        ]);
        $body = curl_exec($ch);
        $code = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);
        return ['body' => ($body === false ? null : $body), 'httpCode' => $code, 'error' => $err];
    }

    // Streams fallback: no gzip, and 'timeout' is read-inactivity based (not a
    // total cap) — acceptable only because curl is present on CI and most hosts.
    $ctx = stream_context_create(['http' => [
        'timeout'         => $timeout,
        'user_agent'      => $userAgent,
        'follow_location' => 1,
        'max_redirects'   => 5,
        'ignore_errors'   => true,   // still return body (and headers) on 4xx/5xx
    ]]);
    $body = @file_get_contents($url, false, $ctx);
    $code = 0;
    if (isset($http_response_header[0])
        && preg_match('#^HTTP/\S+\s+(\d{3})#', $http_response_header[0], $m)) {
        $code = (int)$m[1];
    }
    $err = ($body === false && $code === 0) ? 'stream fetch failed (timeout or connection error)' : '';
    return ['body' => ($body === false ? null : $body), 'httpCode' => $code, 'error' => $err];
}

/**
 * Fetch a URL with bounded retries and exponential backoff + jitter.
 *
 * @param string        $url
 * @param array         $options   attempts(4) baseDelay(2s) connectTimeout(10s)
 *                                 timeout(60s) minBytes(1) userAgent
 * @param callable|null $transport fn(string $url, array $opts): array{body:?string,httpCode:int,error:string}
 * @param callable|null $sleeper   fn(int $milliseconds): void
 * @param callable|null $logger    fn(string $line): void
 * @return array{ok: bool, body: ?string, attempts: int, httpCode: int, error: string}
 */
function fetchUrlWithRetry(
    string $url,
    array $options = [],
    ?callable $transport = null,
    ?callable $sleeper = null,
    ?callable $logger = null
): array {
    $attempts  = max(1, (int)($options['attempts'] ?? 4));
    $baseDelay = max(1, (int)($options['baseDelay'] ?? 2));   // seconds
    $minBytes  = max(1, (int)($options['minBytes'] ?? 1));
    $transport = $transport ?: 'defaultHttpTransport';
    $sleeper   = $sleeper   ?: function (int $ms): void { usleep($ms * 1000); };
    $logger    = $logger    ?: function (string $line): void { echo $line . "\n"; };

    $last = ['httpCode' => 0, 'error' => 'not attempted'];
    $used = 0;

    for ($i = 1; $i <= $attempts; $i++) {
        $used  = $i;
        $start = microtime(true);
        $res   = $transport($url, $options);
        $ms    = (int)round((microtime(true) - $start) * 1000);
        $bytes = is_string($res['body']) ? strlen($res['body']) : 0;
        $code  = (int)$res['httpCode'];

        // Success: a 2xx response with a plausible amount of data.
        if ($code >= 200 && $code < 300 && $bytes >= $minBytes) {
            $logger("Fetch attempt $i/$attempts: HTTP $code, $bytes bytes, {$ms}ms — OK");
            return ['ok' => true, 'body' => $res['body'], 'attempts' => $i, 'httpCode' => $code, 'error' => ''];
        }

        // A 2xx with too little data is a truncated / garbage response — retry it
        // rather than let the caller misparse it as "zero results".
        if ($code >= 200 && $code < 300) {
            $res['error'] = "body too small ($bytes bytes, expected >= $minBytes)";
            $retryable = true;
        } else {
            $retryable = isRetryableHttpFailure($code, (string)$res['error']);
        }

        $last = $res;
        $logger("Fetch attempt $i/$attempts: HTTP $code, $bytes bytes, {$ms}ms — FAILED: {$res['error']}"
            . ($retryable ? '' : ' (not retryable)'));

        if (!$retryable || $i === $attempts) {
            break;
        }

        // Exponential backoff (baseDelay * 2^(i-1)) with 0–1000ms full jitter to
        // decorrelate simultaneous callers (e.g. the alpha/beta matrix legs).
        $delayMs = $baseDelay * (2 ** ($i - 1)) * 1000 + random_int(0, 1000);
        $logger("Retrying in {$delayMs}ms ...");
        $sleeper($delayMs);
    }

    $err = (string)$last['error'];
    return [
        'ok'       => false,
        'body'     => null,
        'attempts' => $used,
        'httpCode' => (int)$last['httpCode'],
        'error'    => $err !== '' ? $err : 'HTTP ' . (int)$last['httpCode'],
    ];
}
