<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Exceptions;

use Throwable;

/**
 * An advisory feed couldn't be reached or answered with something unexpected.
 */
class SourceUnavailable extends SecurityAdvisoriesException
{
    public function __construct(public readonly string $source, string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    public static function because(string $source, string $reason, ?Throwable $previous = null): self
    {
        return new self($source, "{$source} couldn't be reached: {$reason}.", $previous);
    }
}
