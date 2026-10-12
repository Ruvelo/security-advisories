<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Http;

use Http\Discovery\Psr17FactoryDiscovery;
use Http\Discovery\Psr18ClientDiscovery;
use JsonException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Throwable;

/**
 * Talks JSON over PSR-18 / PSR-17. Pass your own client and factories, or let
 * php-http/discovery find whatever the app has installed. Timeouts and
 * redirects are the client's business: configure them there.
 */
final class JsonClient
{
    public const USER_AGENT = 'ruvelo/security-advisories (+https://github.com/Ruvelo/security-advisories)';

    private ?ClientInterface $client;
    private ?RequestFactoryInterface $requests;
    private ?StreamFactoryInterface $streams;

    /**
     * @param int $tries Attempts per request; a refused connection or a 5xx is tried again
     */
    public function __construct(
        ?ClientInterface $client = null,
        ?RequestFactoryInterface $requests = null,
        ?StreamFactoryInterface $streams = null,
        private readonly string $userAgent = self::USER_AGENT,
        private readonly int $tries = 2,
    ) {
        $this->client = $client;
        $this->requests = $requests;
        $this->streams = $streams;
    }

    /**
     * @return array<mixed>
     *
     * @throws SourceUnavailable
     */
    public function get(string $source, string $url): array
    {
        return $this->send($source, fn (): RequestInterface => $this->request('GET', $url));
    }

    /**
     * A GET answered as text (markdown, plain text, HTML), for feeds that
     * aren't JSON. Same retries and error handling as get().
     *
     * @param string $accept The Accept header to send
     *
     * @throws SourceUnavailable
     */
    public function getText(string $source, string $url, string $accept = 'text/plain, text/markdown, */*;q=0.5'): string
    {
        return $this->fetch($source, fn (): RequestInterface => $this->request('GET', $url)->withHeader('Accept', $accept));
    }

    /**
     * @param array<mixed> $body
     * @return array<mixed>
     *
     * @throws SourceUnavailable
     */
    public function postJson(string $source, string $url, array $body): array
    {
        $json = json_encode($body);

        return $this->send($source, fn (): RequestInterface => $this->request('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streams()->createStream($json === false ? '{}' : $json)));
    }

    /**
     * @param string $body An already encoded form body
     * @return array<mixed>
     *
     * @throws SourceUnavailable
     */
    public function postForm(string $source, string $url, string $body): array
    {
        return $this->send($source, fn (): RequestInterface => $this->request('POST', $url)
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streams()->createStream($body)));
    }

    /**
     * One POST of a JSON body, answered as it came: status, headers and the
     * raw body (what a signature covers). Tried once: a caller with a
     * fallback would rather use it than wait for a second attempt.
     *
     * @param array<mixed> $body
     * @param array<string, string> $headers
     * @return array{status: int, headers: array<string, string>, body: string}
     *
     * @throws SourceUnavailable When there is no answer at all
     */
    public function postJsonRaw(string $source, string $url, array $body, array $headers = []): array
    {
        $json = json_encode($body, JSON_UNESCAPED_SLASHES);
        $request = $this->request('POST', $url)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->streams()->createStream($json === false ? '{}' : $json));

        foreach ($headers as $name => $value) {
            $request = $request->withHeader($name, $value);
        }

        try {
            $response = $this->client()->sendRequest($request);
            $content = (string) $response->getBody();
        } catch (SourceUnavailable $e) {
            throw $e;
        } catch (Throwable $e) {
            throw SourceUnavailable::because($source, $e->getMessage(), $e);
        }

        $flat = [];
        foreach (array_keys($response->getHeaders()) as $name) {
            $flat[strtolower((string) $name)] = $response->getHeaderLine((string) $name);
        }

        return ['status' => $response->getStatusCode(), 'headers' => $flat, 'body' => $content];
    }

    /**
     * A copy whose requests give up after $seconds, for a source with a
     * fallback behind it. Your own client is kept as it is unless it can
     * derive a copy with new options (Symfony's Psr18Client can); without a
     * client of your own, one with that timeout is built from Symfony
     * HttpClient or Guzzle when either is installed. Otherwise the deadline is
     * the client's own: callers measure and treat a slow answer as none.
     */
    public function withDeadline(float $seconds): self
    {
        $client = $this->client === null ? self::timedClient($seconds) : self::retimed($this->client, $seconds);

        return new self($client ?? $this->client, $this->requests, $this->streams, $this->userAgent, 1);
    }

    private static function retimed(ClientInterface $client, float $seconds): ClientInterface
    {
        if (method_exists($client, 'withOptions')) {
            try {
                $copy = $client->withOptions(['timeout' => $seconds, 'max_duration' => $seconds]);

                return $copy instanceof ClientInterface ? $copy : $client;
            } catch (Throwable) {
                return $client;
            }
        }

        return $client;
    }

    private static function timedClient(float $seconds): ?ClientInterface
    {
        // Named as strings: both are optional, so neither is a dependency.
        $symfony = 'Symfony\\Component\\HttpClient\\Psr18Client';
        $factory = 'Symfony\\Component\\HttpClient\\HttpClient';
        $guzzle = 'GuzzleHttp\\Client';

        try {
            if (class_exists($symfony) && class_exists($factory)) {
                $client = new $symfony($factory::create(['timeout' => $seconds, 'max_duration' => $seconds]));
            } elseif (class_exists($guzzle)) {
                $client = new $guzzle(['timeout' => $seconds, 'connect_timeout' => min($seconds, 3.0)]);
            } else {
                return null;
            }
        } catch (Throwable) {
            return null;
        }

        return $client instanceof ClientInterface ? $client : null;
    }

    /**
     * @param callable(): RequestInterface $build
     * @return array<mixed>
     */
    private function send(string $source, callable $build): array
    {
        $body = $this->fetch($source, $build);

        try {
            $data = json_decode($body, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw SourceUnavailable::because($source, 'it didn\'t answer with JSON');
        }

        if (! is_array($data)) {
            throw SourceUnavailable::because($source, 'it didn\'t answer with a JSON object');
        }

        return $data;
    }

    /**
     * @param callable(): RequestInterface $build
     */
    private function fetch(string $source, callable $build): string
    {
        $response = null;
        $failure = 'no answer';

        for ($attempt = 1; $attempt <= max(1, $this->tries); $attempt++) {
            try {
                $response = $this->client()->sendRequest($build());
            } catch (ClientExceptionInterface $e) {
                $failure = $e->getMessage();
                $response = null;

                continue;
            } catch (SourceUnavailable $e) {
                throw $e;
            } catch (Throwable $e) {
                throw SourceUnavailable::because($source, $e->getMessage(), $e);
            }

            if ($response->getStatusCode() < 500) {
                break;
            }
        }

        if (! $response instanceof ResponseInterface) {
            throw SourceUnavailable::because($source, $failure);
        }

        if ($response->getStatusCode() < 200 || $response->getStatusCode() >= 300) {
            throw SourceUnavailable::because($source, 'it answered HTTP '.$response->getStatusCode());
        }

        try {
            return (string) $response->getBody();
        } catch (Throwable $e) {
            throw SourceUnavailable::because($source, $e->getMessage(), $e);
        }
    }

    private function request(string $method, string $url): RequestInterface
    {
        return $this->requests()->createRequest($method, $url)
            ->withHeader('Accept', 'application/json')
            ->withHeader('User-Agent', $this->userAgent);
    }

    private function client(): ClientInterface
    {
        return $this->client ??= $this->discover(fn (): ClientInterface => Psr18ClientDiscovery::find(), 'PSR-18 client', 'symfony/http-client or guzzlehttp/guzzle');
    }

    private function requests(): RequestFactoryInterface
    {
        return $this->requests ??= $this->discover(fn (): RequestFactoryInterface => Psr17FactoryDiscovery::findRequestFactory(), 'PSR-17 request factory', 'nyholm/psr7');
    }

    private function streams(): StreamFactoryInterface
    {
        return $this->streams ??= $this->discover(fn (): StreamFactoryInterface => Psr17FactoryDiscovery::findStreamFactory(), 'PSR-17 stream factory', 'nyholm/psr7');
    }

    /**
     * @template T of object
     *
     * @param callable(): T $find
     * @return T
     */
    private function discover(callable $find, string $what, string $suggestion): object
    {
        try {
            return $find();
        } catch (Throwable $e) {
            throw new SourceUnavailable('HTTP', "No {$what} found. Pass one in, or install {$suggestion}.", $e);
        }
    }
}
