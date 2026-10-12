<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Tests\Support\ArrayCache;
use Ruvelo\SecurityAdvisories\Tests\Support\BrokenCache;
use Ruvelo\SecurityAdvisories\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Tests\Support\NetworkError;

class TextFetchTest extends TestCase
{
    private MockClient $client;

    private Psr17Factory $factory;

    protected function setUp(): void
    {
        $this->client = new MockClient();
        $this->factory = new Psr17Factory();
    }

    private function http(int $tries = 2): JsonClient
    {
        return new JsonClient($this->client, $this->factory, $this->factory, tries: $tries);
    }

    private function text(string $body, int $status = 200): \Psr\Http\Message\ResponseInterface
    {
        return $this->factory->createResponse($status)->withHeader('Content-Type', 'text/markdown')->withBody($this->factory->createStream($body));
    }

    public function testGetTextReturnsTheBodyAsItIs(): void
    {
        $body = "---\ntitle: Advisory\n---\n\n{ \"not\": \"json\" }\n";
        $this->client->on('GET', 'friendsofpresta', $this->text($body));

        $this->assertSame($body, $this->http()->getText('Friends of Presta', 'https://raw.friendsofpresta.test/advisory.md'));
    }

    public function testGetTextSendsATextAcceptHeaderAndTheUserAgent(): void
    {
        $this->client->on('GET', 'x.test', $this->text('ok'));

        $this->http()->getText('Test', 'https://x.test/a.md');
        $this->http()->getText('Test', 'https://x.test/b.md', 'text/html');

        $this->assertStringContainsString('text/plain', $this->client->requests[0]->getHeaderLine('Accept'));
        $this->assertSame('text/html', $this->client->requests[1]->getHeaderLine('Accept'));
        $this->assertSame(JsonClient::USER_AGENT, $this->client->requests[0]->getHeaderLine('User-Agent'));
    }

    public function testGetTextRetriesAServerErrorLikeGetDoes(): void
    {
        $this->client->on('GET', 'x.test', $this->text('oops', 502), $this->text('fine'));

        $this->assertSame('fine', $this->http()->getText('Test', 'https://x.test/a.md'));
        $this->assertCount(2, $this->client->requests);
    }

    public function testGetTextFailuresAreSourceUnavailable(): void
    {
        $this->client->on('GET', 'gone.test', $this->text('no', 404));
        $this->client->on('GET', 'down.test', fn (\Psr\Http\Message\RequestInterface $r) => throw new NetworkError($r));

        foreach (['gone.test', 'down.test'] as $host) {
            try {
                $this->http()->getText('Friends of Presta', 'https://'.$host.'/a.md');
                $this->fail('Expected SourceUnavailable');
            } catch (SourceUnavailable $e) {
                $this->assertSame('Friends of Presta', $e->source);
            }
        }
    }

    public function testGetStillOnlyAcceptsJson(): void
    {
        $this->client->on('GET', 'x.test', $this->text('# markdown'));

        $this->expectException(SourceUnavailable::class);
        $this->http()->get('Test', 'https://x.test/a.md');
    }

    public function testTextIsCachedForItsTtl(): void
    {
        $cache = new ArrayCache();
        $responses = new ResponseCache($cache, new Ttls());
        $fetches = 0;
        $fetch = function () use (&$fetches): string {
            return 'body '.++$fetches;
        };

        $answers = [];
        foreach ([false, false, true, false] as $fresh) {
            $answers[] = $responses->rememberText('presta', 3600, $fresh, $fetch);
        }

        $this->assertSame(['body 1', 'body 1', 'body 2', 'body 2'], $answers, 'fresh skips the cache and refills it');
        $this->assertSame([3600], array_values(array_unique($cache->ttls)));
        $this->assertSame(2, $fetches);
    }

    public function testTextAndArrayEntriesNeverMixUnderOneKey(): void
    {
        $responses = new ResponseCache(new ArrayCache(), new Ttls());

        $responses->remember('k', 60, false, fn (): array => ['a' => 1]);
        $text = $responses->rememberText('k', 60, false, fn (): string => 'text');

        $this->assertSame('text', $text);
        $this->assertSame(['a' => 1], $responses->get('k', 60));
        $this->assertSame('text', $responses->getText('k', 60));
    }

    public function testNoCacheOrAZeroTtlAlwaysFetches(): void
    {
        $fetches = 0;
        $fetch = function () use (&$fetches): string {
            return 'v'.++$fetches;
        };

        $none = new ResponseCache(null, new Ttls());
        $this->assertSame('v1', $none->rememberText('k', 60, false, $fetch));
        $this->assertSame('v2', $none->rememberText('k', 60, false, $fetch));

        $cache = new ArrayCache();
        $zero = new ResponseCache($cache, new Ttls());
        $this->assertSame('v3', $zero->rememberText('k', 0, false, $fetch));
        $this->assertSame('v4', $zero->rememberText('k', 0, false, $fetch));
        $this->assertSame([], $cache->items);
    }

    public function testACacheThatThrowsIsSkipped(): void
    {
        $this->assertSame('live', (new ResponseCache(new BrokenCache(), new Ttls()))->rememberText('k', 60, false, fn (): string => 'live'));
    }
}
