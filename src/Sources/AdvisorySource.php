<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\InstalledPackage;

/**
 * Something that knows which advisories apply to installed packages. Write
 * one for a platform's own advisory feed and give it to the Scanner.
 */
interface AdvisorySource
{
    public function supports(Ecosystem $ecosystem): bool;

    /**
     * The advisories that apply to these exact versions.
     *
     * @param list<InstalledPackage> $packages
     * @param bool $fresh Skip any cache
     * @return list<AdvisoryMatch>
     *
     * @throws SourceUnavailable When the feed can't be read in full: a partial answer must not look like a clean one
     */
    public function find(array $packages, bool $fresh = false): array;
}
