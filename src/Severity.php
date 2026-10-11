<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * How bad an advisory says it is. NotRated is common for older advisories,
 * which were published before severities were recorded.
 */
enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case NotRated = 'not_rated';

    /**
     * Reads the spellings the sources use: Packagist's "critical", "high",
     * "medium", "low" and GitHub's "MODERATE" (through OSV). Anything else is
     * NotRated rather than a guess.
     */
    public static function parse(?string $value): self
    {
        return match (strtolower(trim((string) $value))) {
            'critical' => self::Critical,
            'high' => self::High,
            'medium', 'moderate' => self::Medium,
            'low' => self::Low,
            default => self::NotRated,
        };
    }

    /**
     * Higher is worse. NotRated sits between medium and low: an advisory
     * without a score is not evidence that it is harmless.
     */
    public function rank(): int
    {
        return match ($this) {
            self::Critical => 4,
            self::High => 3,
            self::Medium => 2,
            self::NotRated => 1,
            self::Low => 0,
        };
    }

    public function atLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    public function label(): string
    {
        return match ($this) {
            self::NotRated => 'Not rated',
            default => ucfirst($this->value),
        };
    }
}
