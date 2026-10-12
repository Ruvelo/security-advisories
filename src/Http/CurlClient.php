<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Http;

use Closure;
use Http\Discovery\Psr17FactoryDiscovery;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Throwable;

/**
 * A small PSR-18 client on ext-curl, for platforms where discovery finds no
 * client (or finds one that conflicts with the host application's HTTP stack).
 * Pass it to JsonClient. It follows a few redirects over http(s) only,
 * verifies TLS, and applies the timeouts you give it. Anything but an answer
 * (DNS, connection, timeout, TLS) is thrown as CurlException; HTTP error
 * statuses are returned as responses, as PSR-18 wants.
 *
 * It still needs PSR-17 factories for the response: pass them, or let
 * php-http/discovery find any (nyholm/psr7, guzzle/psr7, laminas...).
 */
final class CurlClient implements ClientInterface
{
    private ?ResponseFactoryInterface $responses;
    private ?StreamFactoryInterface $streams;

    /** @var (Closure(string, string, array<string, string>, string): array{status: int, headers: array<string, list<string>>, body: string})|null */
    private readonly ?Closure $transport;

    /**
     * @param int $maxRedirects 0 never follows a redirect
     * @param (callable(string, string, array<string, string>, string): array{status: int, headers: array<string, list<string>>, body: string})|null $transport Replaces curl: gets method, url, headers and body. For tests, or to route through something else
     */
    public function __construct(
        ?ResponseFactoryInterface $responses = null,
        ?StreamFactoryInterface $streams = null,
        private readonly float $timeout = 10.0,
        private readonly float $connectTimeout = 5.0,
        private readonly int $maxRedirects = 3,
        ?callable $transport = null,
    ) {
        $this->responses = $responses;
        $this->streams = $streams;
        $this->transport = $transport === null ? null : $transport(...);
    }

    public static function isAvailable(): bool
    {
        return function_exists('curl_init');
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $uri = $request->getUri();
        $scheme = strtolower($uri->getScheme());

        if ($scheme !== 'http' && $scheme !== 'https') {
            throw new CurlException('Only http and https URLs are supported, got "'.$scheme.'".', $request);
        }

        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[(string) $name] = implode(', ', $values);
        }

        $body = (string) $request->getBody();

        try {
            $answer = ($this->transport ?? $this->curl(...))($request->getMethod(), (string) $uri, $headers, $body);
        } catch (CurlException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new CurlException($e->getMessage(), $request, $e);
        }

        try {
            $response = $this->responses()->createResponse($answer['status']);
            foreach ($answer['headers'] as $name => $values) {
                foreach ($values as $value) {
                    $response = $response->withAddedHeader($name, $value);
                }
            }

            return $response->withBody($this->streams()->createStream($answer['body']));
        } catch (SourceUnavailable $e) {
            throw new CurlException($e->getMessage(), $request, $e);
        }
    }

    /**
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, list<string>>, body: string}
     */
    private function curl(string $method, string $url, array $headers, string $body): array
    {
        if (! self::isAvailable()) {
            throw new \RuntimeException('ext-curl is not installed.');
        }

        $handle = curl_init();
        $sent = [];
        foreach ($headers as $name => $value) {
            $sent[] = $name.': '.$value;
        }

        $received = [];
        foreach ([
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => $sent,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => false,
            CURLOPT_ENCODING => '',
            CURLOPT_TIMEOUT_MS => max(1, (int) round($this->timeout * 1000)),
            CURLOPT_CONNECTTIMEOUT_MS => max(1, (int) round($this->connectTimeout * 1000)),
            CURLOPT_FOLLOWLOCATION => $this->maxRedirects > 0,
            CURLOPT_MAXREDIRS => $this->maxRedirects,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_NOSIGNAL => true,
            // One block per response; the last one is the final answer after redirects.
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$received): int {
                $trimmed = trim($line);
                if (str_starts_with($trimmed, 'HTTP/')) {
                    $received = [];
                } elseif (str_contains($trimmed, ':')) {
                    [$name, $value] = explode(':', $trimmed, 2);
                    $received[trim($name)][] = trim($value);
                }

                return strlen($line);
            },
        ] as $option => $value) {
            curl_setopt($handle, $option, $value);
        }

        if ($method === 'HEAD') {
            curl_setopt($handle, CURLOPT_NOBODY, true);
        } elseif ($body !== '') {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }

        $content = curl_exec($handle);

        if ($content === false || ! is_string($content)) {
            $message = curl_error($handle);
            curl_close($handle);

            throw new \RuntimeException($message !== '' ? $message : 'no answer');
        }

        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        curl_close($handle);

        return ['status' => $status, 'headers' => $received, 'body' => $content];
    }

    private function responses(): ResponseFactoryInterface
    {
        try {
            return $this->responses ??= Psr17FactoryDiscovery::findResponseFactory();
        } catch (Throwable $e) {
            throw SourceUnavailable::because('HTTP', 'No PSR-17 response factory found. Pass one in, or install nyholm/psr7.', $e);
        }
    }

    private function streams(): StreamFactoryInterface
    {
        try {
            return $this->streams ??= Psr17FactoryDiscovery::findStreamFactory();
        } catch (Throwable $e) {
            throw SourceUnavailable::because('HTTP', 'No PSR-17 stream factory found. Pass one in, or install nyholm/psr7.', $e);
        }
    }
}
