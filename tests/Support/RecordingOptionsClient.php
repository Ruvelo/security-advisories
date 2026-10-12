<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Support;

use Nyholm\Psr7\Factory\Psr17Factory;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * A PSR-18 client with Symfony's withOptions(), recording what it was given.
 */
class RecordingOptionsClient implements ClientInterface
{
    /** @var list<array<string, mixed>> */
    public static array $options = [];

    /**
     * @param array<string, mixed> $options
     */
    public function withOptions(array $options): static
    {
        static::$options[] = $options;

        return clone $this;
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        return (new Psr17Factory())->createResponse(204);
    }
}
