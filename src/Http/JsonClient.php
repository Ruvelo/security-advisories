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
     * @param callable(): RequestInterface $build
     * @return array<mixed>
     */
    private function send(string $source, callable $build): array
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
            $data = json_decode((string) $response->getBody(), true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw SourceUnavailable::because($source, 'it didn\'t answer with JSON');
        }

        if (! is_array($data)) {
            throw SourceUnavailable::because($source, 'it didn\'t answer with a JSON object');
        }

        return $data;
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
