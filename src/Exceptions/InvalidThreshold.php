<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Exceptions;

class InvalidThreshold extends SecurityAdvisoriesException
{
    public static function for(string $value): self
    {
        return new self("\"{$value}\" isn't a threshold. Use exploited, critical, high, medium or any.");
    }
}
