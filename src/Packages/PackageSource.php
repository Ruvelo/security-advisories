<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Packages;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\InstalledPackage;

/**
 * Where a list of installed packages comes from: a lockfile, or an inventory
 * an adapter builds (Joomla extensions, PrestaShop modules, Shopware plugins).
 */
interface PackageSource
{
    /**
     * The one ecosystem every package here belongs to.
     */
    public function ecosystem(): Ecosystem;

    /**
     * What this is, for messages: "composer.lock at /srv/app/composer.lock".
     */
    public function describe(): string;

    /**
     * Whether a missing list is a problem. A project without package-lock.json
     * is normal; one without composer.lock usually isn't.
     */
    public function isRequired(): bool;

    /**
     * @return list<InstalledPackage>|null Null when there is nothing to read (no such file)
     *
     * @throws PackagesUnreadable
     */
    public function packages(): ?array;
}
