<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Packages;

use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\InstalledPackage;

/**
 * Reads the exact versions npm installed from package-lock.json, lockfile
 * versions 1 to 3, including packages nested under other packages. A missing
 * file is normal: not every project has one.
 */
final class NpmLockReader implements PackageSource
{
    public function __construct(private readonly string $path, private readonly bool $includeDev = true)
    {
    }

    public function ecosystem(): Ecosystem
    {
        return Ecosystem::Npm;
    }

    public function describe(): string
    {
        return 'package-lock.json at '.$this->path;
    }

    public function isRequired(): bool
    {
        return false;
    }

    public function packages(): ?array
    {
        $data = JsonFile::read($this->path);

        if ($data === null) {
            return null;
        }

        if (is_array($data['packages'] ?? null)) {
            $found = $this->fromPackages($data['packages']);
        } elseif (is_array($data['dependencies'] ?? null)) {
            $found = $this->fromDependencies($data['dependencies']);
        } else {
            throw PackagesUnreadable::at($this->path, 'it has neither "packages" nor "dependencies"');
        }

        // The same version can sit in several places in node_modules: check it once,
        // and count it as a production dependency if any copy is one.
        $unique = [];
        foreach ($found as $package) {
            $key = $package->name.'@'.$package->version;
            if (! isset($unique[$key]) || ! $package->isDev) {
                $unique[$key] = $package;
            }
        }

        return array_values(array_filter($unique, fn (InstalledPackage $package): bool => $this->includeDev || ! $package->isDev));
    }

    /**
     * Lockfile v2 and v3: a flat map of install paths.
     *
     * @param array<mixed> $entries
     * @return list<InstalledPackage>
     */
    private function fromPackages(array $entries): array
    {
        $packages = [];

        foreach ($entries as $path => $entry) {
            if (! is_string($path) || $path === '' || ! is_array($entry) || ($entry['link'] ?? false) === true) {
                continue;
            }

            // Only what's under node_modules: other paths are the project's own workspaces.
            $fromPath = $this->nameFromPath($path);
            $name = is_string($entry['name'] ?? null) ? $entry['name'] : $fromPath;
            $version = $entry['version'] ?? null;

            if ($fromPath === null || $name === null || ! is_string($version) || $version === '') {
                continue;
            }

            $packages[] = new InstalledPackage(Ecosystem::Npm, $name, $version, ($entry['dev'] ?? false) === true);
        }

        return $packages;
    }

    /**
     * Lockfile v1: dependencies nested in dependencies.
     *
     * @param array<mixed> $entries
     * @return list<InstalledPackage>
     */
    private function fromDependencies(array $entries): array
    {
        $packages = [];

        foreach ($entries as $name => $entry) {
            if (! is_string($name) || ! is_array($entry)) {
                continue;
            }

            if (is_string($entry['version'] ?? null) && $entry['version'] !== '' && ! str_contains($entry['version'], ':')) {
                $packages[] = new InstalledPackage(Ecosystem::Npm, $name, $entry['version'], ($entry['dev'] ?? false) === true);
            }

            if (is_array($entry['dependencies'] ?? null)) {
                $packages = [...$packages, ...$this->fromDependencies($entry['dependencies'])];
            }
        }

        return $packages;
    }

    /**
     * "node_modules/a/node_modules/@scope/b" is "@scope/b".
     */
    private function nameFromPath(string $path): ?string
    {
        $at = strrpos($path, 'node_modules/');

        return $at === false ? null : substr($path, $at + strlen('node_modules/'));
    }
}
