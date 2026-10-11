<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * A published security advisory for one package, from Packagist or OSV,
 * in the same shape whichever source it came from.
 */
final readonly class Advisory
{
    /**
     * @param string|null $affectedVersions A Composer constraint when the source gives one
     * @param string|null $fixedIn The version that fixes it, when the source says so directly
     */
    public function __construct(
        public string $id,
        public Ecosystem $ecosystem,
        public string $package,
        public string $title,
        public ?string $link = null,
        public ?string $cve = null,
        public Severity $severity = Severity::NotRated,
        public ?string $affectedVersions = null,
        public ?string $fixedIn = null,
        public ?string $reportedAt = null,
    ) {
    }
}
