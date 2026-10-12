<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Http;

use Psr\Http\Client\NetworkExceptionInterface;
use Psr\Http\Message\RequestInterface;
use RuntimeException;
use Throwable;

/**
 * The request couldn't be made or got no answer (DNS, connection, timeout, TLS).
 */
final class CurlException extends RuntimeException implements NetworkExceptionInterface
{
    public function __construct(string $message, private readonly RequestInterface $request, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    public function getRequest(): RequestInterface
    {
        return $this->request;
    }
}
