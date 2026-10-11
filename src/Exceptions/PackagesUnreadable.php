<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Exceptions;

/**
 * A lockfile or inventory exists but can't be understood.
 */
class PackagesUnreadable extends SecurityAdvisoriesException
{
    public static function at(string $path, string $reason): self
    {
        return new self("Couldn't read {$path}: {$reason}.");
    }
}
