<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\NetworkExceptionInterface;
use Ruvelo\SecurityAdvisories\Http\CurlClient;
use Ruvelo\SecurityAdvisories\Http\CurlException;

class CurlClientTransportTest extends TestCase
{
    public function testAnInjectedTransportReplacesCurl(): void
    {
        $factory = new Psr17Factory();
        /** @var array{string, string, array<string, string>, string} $seen */
        $seen = ['', '', [], ''];
        $client = new CurlClient($factory, $factory, transport: function (string $method, string $url, array $headers, string $body) use (&$seen): array {
            $seen = [$method, $url, $headers, $body];

            return ['status' => 201, 'headers' => ['X-A' => ['1', '2']], 'body' => 'made'];
        });

        $response = $client->sendRequest($factory->createRequest('PUT', 'https://example.test/x')->withHeader('Accept', 'text/plain')->withBody($factory->createStream('data')));

        $this->assertSame(201, $response->getStatusCode());
        $this->assertSame(['1', '2'], $response->getHeader('X-A'));
        $this->assertSame('made', (string) $response->getBody());
        $this->assertSame(['PUT', 'https://example.test/x'], [$seen[0], $seen[1]]);
        $this->assertSame('text/plain', $seen[2]['Accept']);
        $this->assertSame('data', $seen[3]);
    }

    public function testATransportThatFailsBecomesACurlException(): void
    {
        $factory = new Psr17Factory();
        $client = new CurlClient($factory, $factory, transport: fn (): array => throw new \RuntimeException('could not resolve host'));

        try {
            $client->sendRequest($factory->createRequest('GET', 'https://example.test/'));
            $this->fail('Expected an exception');
        } catch (CurlException $e) {
            $this->assertSame('could not resolve host', $e->getMessage());
            $this->assertInstanceOf(NetworkExceptionInterface::class, $e);
        }
    }
}
