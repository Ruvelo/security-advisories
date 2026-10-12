<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * A package that was inventoried but couldn't be checked, because no advisory
 * source covers its ecosystem (a zip-installed Shopware plugin, say). That is
 * a fact about coverage, not a failure: it doesn't make a report incomplete.
 */
final readonly class UncheckedPackage
{
    public function __construct(
        public InstalledPackage $package,
        public string $reason,
    ) {
    }

    /**
     * @return array{ecosystem: string, name: string, version: string, dev: bool, meta: array<string, scalar>, reason: string}
     */
    public function toArray(): array
    {
        return [
            'ecosystem' => $this->package->ecosystem->value,
            'name' => $this->package->name,
            'version' => $this->package->version,
            'dev' => $this->package->isDev,
            'meta' => $this->package->metadata,
            'reason' => $this->reason,
        ];
    }

    /**
     * @param array<mixed> $data What toArray() gave
     */
    public static function fromArray(array $data): ?self
    {
        $ecosystem = is_string($data['ecosystem'] ?? null) ? Ecosystem::tryFrom($data['ecosystem']) : null;

        if ($ecosystem === null || ! is_string($data['name'] ?? null) || $data['name'] === '') {
            return null;
        }

        $meta = is_array($data['meta'] ?? null) ? $data['meta'] : [];

        /** @var array<string, scalar> $meta */
        return new self(
            new InstalledPackage($ecosystem, $data['name'], is_string($data['version'] ?? null) ? $data['version'] : '', ($data['dev'] ?? false) === true, $meta),
            is_string($data['reason'] ?? null) ? $data['reason'] : '',
        );
    }
}
