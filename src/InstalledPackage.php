<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * One installed package or extension, as a lockfile or an inventory records it.
 */
final readonly class InstalledPackage
{
    /**
     * Optional facts an adapter wants to carry along (`active: false`,
     * `source: 'zip'`). They end up on every Finding for this package.
     *
     * @var array<string, scalar>
     */
    public array $metadata;

    /**
     * @param array<array-key, mixed> $metadata Scalars with string keys (`array<string, scalar>`); anything else is dropped
     */
    public function __construct(
        public Ecosystem $ecosystem,
        public string $name,
        public string $version,
        public bool $isDev = false,
        array $metadata = [],
    ) {
        $kept = [];
        foreach ($metadata as $key => $value) {
            if (is_string($key) && is_scalar($value)) {
                $kept[$key] = $value;
            }
        }

        $this->metadata = $kept;
    }
}
