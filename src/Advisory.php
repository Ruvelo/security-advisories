<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * A published security advisory for one package, from Packagist, OSV or
 * Valtry, in the same shape whichever source it came from.
 */
final readonly class Advisory
{
    /**
     * @param string|null $affectedVersions A Composer constraint when the source gives one
     * @param string|null $fixedIn The version that fixes it, when the source says so directly
     * @param KevEntry|null $kev The CISA KEV entry, when the source already says (see $kevKnown)
     * @param bool $kevKnown True when the source checked KEV itself (Valtry): $kev is then the answer, and no catalogue lookup is needed
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
        public ?KevEntry $kev = null,
        public bool $kevKnown = false,
    ) {
    }
}
