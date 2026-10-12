<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Client\NetworkExceptionInterface;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\CurlClient;
use Ruvelo\SecurityAdvisories\Http\CurlException;
use Ruvelo\SecurityAdvisories\Http\JsonClient;

class CurlClientTest extends TestCase
{
    /** @var resource|null */
    private static $server = null;

    private static int $port = 0;

    public static function setUpBeforeClass(): void
    {
        if (! CurlClient::isAvailable() || ! function_exists('proc_open')) {
            return;
        }

        $probe = stream_socket_server('tcp://127.0.0.1:0');
        if ($probe === false) {
            return;
        }
        self::$port = (int) substr((string) stream_socket_get_name($probe, false), strrpos((string) stream_socket_get_name($probe, false), ':') + 1);
        fclose($probe);

        $process = proc_open(
            [PHP_BINARY, '-S', '127.0.0.1:'.self::$port, __DIR__.'/../fixtures/curl-server.php'],
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            ['PHP_CLI_SERVER_WORKERS' => '4'] + getenv(),
        );

        if (! is_resource($process)) {
            return;
        }
        self::$server = $process;

        for ($i = 0; $i < 100; $i++) {
            $socket = @fsockopen('127.0.0.1', self::$port, $errno, $error, 0.1);
            if ($socket !== false) {
                fclose($socket);

                return;
            }
            usleep(50_000);
        }

        self::stopServer();
    }

    public static function tearDownAfterClass(): void
    {
        self::stopServer();
    }

    private static function stopServer(): void
    {
        if (self::$server !== null) {
            proc_terminate(self::$server);
            proc_close(self::$server);
            self::$server = null;
        }
    }

    protected function setUp(): void
    {
        if (self::$server === null) {
            $this->markTestSkipped('No local php -S server (needs ext-curl and proc_open).');
        }
    }

    private function url(string $path): string
    {
        return 'http://127.0.0.1:'.self::$port.$path;
    }

    private function client(float $timeout = 5.0, int $redirects = 3): CurlClient
    {
        $factory = new Psr17Factory();

        return new CurlClient($factory, $factory, timeout: $timeout, maxRedirects: $redirects);
    }

    public function testItIsAPsr18Client(): void
    {
        $this->assertInstanceOf(ClientInterface::class, $this->client());
    }

    public function testItReturnsStatusHeadersAndBody(): void
    {
        $response = $this->client()->sendRequest((new Psr17Factory())->createRequest('GET', $this->url('/text')));

        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame("# Advisory\n\nAffected: <1.2.3\n", (string) $response->getBody());
        $this->assertStringStartsWith('text/markdown', $response->getHeaderLine('content-type'));
        $this->assertSame(['one', 'two'], $response->getHeader('X-Twice'));
    }

    public function testItSendsTheMethodHeadersAndBody(): void
    {
        $factory = new Psr17Factory();
        $request = $factory->createRequest('POST', $this->url('/echo'))
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('User-Agent', 'test-agent')
            ->withBody($factory->createStream('{"a":1}'));

        $echo = json_decode((string) $this->client()->sendRequest($request)->getBody(), true);

        $this->assertSame('POST', $echo['method']);
        $this->assertSame('{"a":1}', $echo['body']);
        $this->assertSame('test-agent', $echo['agent']);
        $this->assertSame('application/json', $echo['type']);
    }

    public function testHttpErrorsAreResponsesNotExceptions(): void
    {
        $factory = new Psr17Factory();

        $this->assertSame(404, $this->client()->sendRequest($factory->createRequest('GET', $this->url('/missing')))->getStatusCode());
        $this->assertSame(503, $this->client()->sendRequest($factory->createRequest('GET', $this->url('/boom')))->getStatusCode());
    }

    public function testItFollowsRedirectsUpToTheLimit(): void
    {
        $factory = new Psr17Factory();

        $followed = $this->client()->sendRequest($factory->createRequest('GET', $this->url('/redirect')));
        $this->assertSame(200, $followed->getStatusCode());
        $this->assertStringStartsWith('text/markdown', $followed->getHeaderLine('Content-Type'));

        $kept = $this->client(redirects: 0)->sendRequest($factory->createRequest('GET', $this->url('/redirect')));
        $this->assertSame(302, $kept->getStatusCode());

        $this->expectException(CurlException::class);
        $this->client()->sendRequest($factory->createRequest('GET', $this->url('/loop')));
    }

    public function testATimeoutIsANetworkException(): void
    {
        $request = (new Psr17Factory())->createRequest('GET', $this->url('/slow'));

        try {
            $this->client(timeout: 0.5)->sendRequest($request);
            $this->fail('Expected a timeout');
        } catch (NetworkExceptionInterface $e) {
            $this->assertSame($request, $e->getRequest());
        }
    }

    public function testARefusedConnectionIsANetworkException(): void
    {
        $this->expectException(CurlException::class);

        $this->client()->sendRequest((new Psr17Factory())->createRequest('GET', 'http://127.0.0.1:1/'));
    }

    public function testOtherSchemesAreRefused(): void
    {
        $this->expectException(CurlException::class);

        $this->client()->sendRequest((new Psr17Factory())->createRequest('GET', 'file:///etc/passwd'));
    }

    public function testJsonClientWorksOverIt(): void
    {
        $factory = new Psr17Factory();
        $http = new JsonClient($this->client(), $factory, $factory);

        $this->assertSame('POST', $http->postJson('Test', $this->url('/echo'), ['x' => 1])['method']);
        $this->assertStringContainsString('Affected: <1.2.3', $http->getText('Test', $this->url('/text')));

        $this->expectException(SourceUnavailable::class);
        $http->get('Test', $this->url('/missing'));
    }
}
