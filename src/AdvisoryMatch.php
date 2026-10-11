<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * What an AdvisorySource returns: an advisory that applies to an installed
 * package, and the version that fixes it when that can be told.
 */
final readonly class AdvisoryMatch
{
    public function __construct(
        public InstalledPackage $package,
        public Advisory $advisory,
        public ?string $fixedIn = null,
    ) {
    }
}
