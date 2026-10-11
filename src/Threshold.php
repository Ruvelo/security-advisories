<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

use Ruvelo\SecurityAdvisories\Exceptions\InvalidThreshold;

/**
 * How bad a finding has to be before a check should fail (an exit code, a
 * health check). Exploited findings always count.
 */
enum Threshold: string
{
    case Exploited = 'exploited';
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Any = 'any';

    /**
     * @throws InvalidThreshold
     */
    public static function parse(string $value): self
    {
        return self::tryFrom(strtolower(trim($value))) ?? throw InvalidThreshold::for($value);
    }

    public function isMetBy(Finding $finding): bool
    {
        return match ($this) {
            self::Exploited => $finding->isExploited(),
            self::Critical => $finding->isExploited() || $finding->severity->atLeast(Severity::Critical),
            self::High => $finding->isExploited() || $finding->severity->atLeast(Severity::High),
            self::Medium => $finding->isExploited() || $finding->severity->atLeast(Severity::Medium),
            self::Any => true,
        };
    }
}
