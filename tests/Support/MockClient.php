<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Support;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client that never touches the network. Routes are matched on the
 * method and a substring of the URL; each answer is a response, an exception
 * to throw, or a callable that gets the request. Unmatched requests get a 404
 * and are listed in $stray, which tests assert is empty.
 */
final class MockClient implements ClientInterface
{
    /** @var list<RequestInterface> */
    public array $requests = [];

    /** @var list<string> */
    public array $stray = [];

    /** @var list<array{string, string, list<ResponseInterface|ClientExceptionInterface|callable>}> */
    private array $routes = [];

    private Psr17Factory $factory;

    public function __construct()
    {
        $this->factory = new Psr17Factory();
    }

    /**
     * @param ResponseInterface|ClientExceptionInterface|callable ...$answers Used in turn; the last one repeats
     */
    public function on(string $method, string $urlContains, ResponseInterface|ClientExceptionInterface|callable ...$answers): self
    {
        $this->routes[] = [$method, $urlContains, array_values($answers)];

        return $this;
    }

    /**
     * @param array<mixed>|string $body
     */
    public function json(array|string $body, int $status = 200): ResponseInterface
    {
        return $this->factory->createResponse($status)
            ->withHeader('Content-Type', 'application/json')
            ->withBody($this->factory->createStream(is_string($body) ? $body : (string) json_encode($body)));
    }

    public function fixture(string $name, int $status = 200): ResponseInterface
    {
        return $this->json((string) file_get_contents(__DIR__.'/../fixtures/'.$name), $status);
    }

    /**
     * The feeds as recorded for Halyard's lockfiles in tests/fixtures.
     */
    public static function feeds(): self
    {
        $client = new self();

        return $client
            ->on('POST', 'packagist.org/api/security-advisories', $client->fixture('packagist.json'))
            ->on('POST', 'api.osv.dev/v1/querybatch', $client->fixture('osv-querybatch.json'))
            ->on('GET', 'api.osv.dev/v1/vulns/', function (RequestInterface $request) use ($client): ResponseInterface {
                $id = basename($request->getUri()->getPath());

                return is_file(__DIR__.'/../fixtures/osv/'.$id.'.json') ? $client->fixture('osv/'.$id.'.json') : $client->json([], 404);
            })
            ->on('GET', 'cisa.gov', $client->fixture('kev.json'));
    }

    /**
     * @return list<RequestInterface>
     */
    public function sentTo(string $urlContains): array
    {
        return array_values(array_filter($this->requests, fn (RequestInterface $r): bool => str_contains((string) $r->getUri(), $urlContains)));
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->requests[] = $request;

        foreach ($this->routes as $i => [$method, $contains, $answers]) {
            if ($request->getMethod() !== $method || ! str_contains((string) $request->getUri(), $contains)) {
                continue;
            }

            $answer = count($answers) > 1 ? array_shift($answers) : $answers[0];
            $this->routes[$i][2] = $answers;

            if ($answer instanceof ClientExceptionInterface) {
                throw $answer;
            }

            return $answer instanceof ResponseInterface ? $answer : $answer($request);
        }

        $this->stray[] = $request->getMethod().' '.$request->getUri();

        return $this->factory->createResponse(404);
    }
}
