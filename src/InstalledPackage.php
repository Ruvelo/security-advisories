<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * One installed package or extension, as a lockfile or an inventory records it.
 */
final readonly class InstalledPackage
{
    public function __construct(
        public Ecosystem $ecosystem,
        public string $name,
        public string $version,
        public bool $isDev = false,
    ) {
    }
}
