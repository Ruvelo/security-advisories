<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Packages;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\InstalledPackage;

/**
 * A list of packages the adapter already has in hand: the extensions a Joomla
 * site reports, the modules PrestaShop lists, the plugins Shopware loaded.
 *
 * Pair it with an AdvisorySource for the same ecosystem. For extensions that
 * are also Composer packages, use Ecosystem::Composer and Packagist covers them.
 */
final class ExtensionList implements PackageSource
{
    /** @var list<InstalledPackage> */
    private readonly array $packages;

    /**
     * @param iterable<InstalledPackage|array{name: string, version: string, dev?: bool}> $packages
     */
    public function __construct(
        iterable $packages,
        private readonly Ecosystem $ecosystem = Ecosystem::Extension,
        private readonly string $label = 'the extension list',
    ) {
        $list = [];

        foreach ($packages as $package) {
            $list[] = $package instanceof InstalledPackage
                ? $package
                : new InstalledPackage($this->ecosystem, $package['name'], $package['version'], $package['dev'] ?? false);
        }

        $this->packages = $list;
    }

    public function ecosystem(): Ecosystem
    {
        return $this->ecosystem;
    }

    public function describe(): string
    {
        return $this->label;
    }

    public function isRequired(): bool
    {
        return true;
    }

    /**
     * @return list<InstalledPackage>
     */
    public function packages(): array
    {
        return $this->packages;
    }
}
