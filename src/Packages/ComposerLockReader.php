<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Packages;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\InstalledPackage;

/**
 * Reads the exact versions Composer installed from composer.lock. Packages
 * from "packages-dev" are flagged isDev; leave them out with $includeDev.
 */
final class ComposerLockReader implements PackageSource
{
    public function __construct(private readonly string $path, private readonly bool $includeDev = true)
    {
    }

    public function ecosystem(): Ecosystem
    {
        return Ecosystem::Composer;
    }

    public function describe(): string
    {
        return 'composer.lock at '.$this->path;
    }

    public function isRequired(): bool
    {
        return true;
    }

    public function packages(): ?array
    {
        $data = JsonFile::read($this->path);

        if ($data === null) {
            return null;
        }

        if (! is_array($data['packages'] ?? null)) {
            throw PackagesUnreadable::at($this->path, 'it has no "packages" list');
        }

        $packages = $this->entries($data['packages'], false);

        if ($this->includeDev && is_array($data['packages-dev'] ?? null)) {
            $packages = [...$packages, ...$this->entries($data['packages-dev'], true)];
        }

        return $packages;
    }

    /**
     * @param array<mixed> $entries
     * @return list<InstalledPackage>
     */
    private function entries(array $entries, bool $dev): array
    {
        $packages = [];

        foreach ($entries as $entry) {
            if (! is_array($entry) || ! is_string($entry['name'] ?? null) || ! is_string($entry['version'] ?? null)) {
                continue;
            }

            // "v3.6.2" and "3.6.2" are the same release; show it the way advisories do.
            $version = (string) preg_replace('/^v(?=\d)/i', '', $entry['version']);

            $packages[] = new InstalledPackage(Ecosystem::Composer, strtolower($entry['name']), $version, $dev);
        }

        return $packages;
    }
}
