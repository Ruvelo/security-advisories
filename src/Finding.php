<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

use JsonSerializable;

/**
 * An advisory that applies to a package that is installed. Immutable.
 */
final readonly class Finding implements JsonSerializable
{
    /** The version of the shape toArray() gives and fromArray() reads. */
    public const SHAPE = 1;

    /**
     * @param list<string> $aliases Other ids for the same vulnerability
     * @param list<string> $links Further references besides $link
     * @param array<string, scalar> $metadata What the adapter attached to the installed package (see InstalledPackage::$metadata)
     */
    public function __construct(
        public Ecosystem $ecosystem,
        public string $package,
        public string $installed,
        public string $advisoryId,
        public string $title,
        public Severity $severity = Severity::NotRated,
        public ?string $link = null,
        public ?string $cve = null,
        public ?string $fixedIn = null,
        public ?string $affectedVersions = null,
        public ?string $reportedAt = null,
        public ?KevEntry $exploited = null,
        public bool $isDev = false,
        public array $aliases = [],
        public array $links = [],
        public array $metadata = [],
    ) {
    }

    public static function from(AdvisoryMatch $match, ?KevEntry $exploited = null): self
    {
        return new self(
            ecosystem: $match->package->ecosystem,
            package: $match->package->name,
            installed: $match->package->version,
            advisoryId: $match->advisory->id,
            title: $match->advisory->title,
            severity: $match->advisory->severity,
            link: $match->advisory->link,
            cve: $match->advisory->cve,
            fixedIn: $match->fixedIn,
            affectedVersions: $match->advisory->affectedVersions,
            reportedAt: $match->advisory->reportedAt,
            exploited: $exploited,
            isDev: $match->package->isDev,
            aliases: $match->advisory->aliases,
            links: $match->advisory->links,
            metadata: $match->package->metadata,
        );
    }

    /**
     * A finding back from what toArray() gave (as an adapter stored it).
     * Null when the data is too incomplete to stand for a finding.
     *
     * @param array<mixed> $data
     */
    public static function fromArray(array $data): ?self
    {
        $ecosystem = is_string($data['ecosystem'] ?? null) ? Ecosystem::tryFrom($data['ecosystem']) : null;
        $string = fn (string $key): ?string => is_string($data[$key] ?? null) && $data[$key] !== '' ? $data[$key] : null;
        $package = $string('package');
        $advisoryId = $string('advisory_id');

        if ($ecosystem === null || $package === null || $advisoryId === null) {
            return null;
        }

        return new self(
            ecosystem: $ecosystem,
            package: $package,
            installed: $string('installed') ?? '',
            advisoryId: $advisoryId,
            title: $string('title') ?? $advisoryId,
            severity: Severity::tryFrom($string('severity') ?? '') ?? Severity::NotRated,
            link: $string('link'),
            cve: $string('cve'),
            fixedIn: $string('fixed_in'),
            affectedVersions: $string('affected_versions'),
            reportedAt: $string('reported_at'),
            exploited: is_array($data['kev'] ?? null) ? KevEntry::fromArray($data['kev']) : null,
            isDev: ($data['dev'] ?? false) === true,
            aliases: self::strings($data['aliases'] ?? null),
            links: self::strings($data['links'] ?? null),
            metadata: self::scalars($data['meta'] ?? null),
        );
    }

    /**
     * What identifies this finding across checks: the same advisory on the
     * same package is the same finding, whichever affected version is installed.
     * Adapters store it, and hand the stored keys back to the Reconciler.
     */
    public function key(): string
    {
        return $this->ecosystem->value.':'.$this->package.':'.$this->advisoryId;
    }

    public function isExploited(): bool
    {
        return $this->exploited !== null;
    }

    /**
     * Sorts findings worst first: exploited in the wild, then by severity,
     * then the most recently exploited, then by package name.
     */
    public static function compare(self $a, self $b): int
    {
        return [$b->isExploited(), $b->severity->rank(), $b->exploited?->dateAdded->getTimestamp() ?? 0, $a->package, $a->advisoryId]
            <=> [$a->isExploited(), $a->severity->rank(), $a->exploited?->dateAdded->getTimestamp() ?? 0, $b->package, $b->advisoryId];
    }

    /**
     * @return array{v: int, key: string, ecosystem: string, package: string, installed: string, dev: bool, advisory_id: string, title: string, severity: string, link: string|null, cve: string|null, fixed_in: string|null, affected_versions: string|null, reported_at: string|null, exploited: bool, kev: array{cve: string, name: string, date_added: string, due_date: string|null, ransomware: bool}|null, aliases: list<string>, links: list<string>, meta: array<string, scalar>}
     */
    public function toArray(): array
    {
        return [
            'v' => self::SHAPE,
            'key' => $this->key(),
            'ecosystem' => $this->ecosystem->value,
            'package' => $this->package,
            'installed' => $this->installed,
            'dev' => $this->isDev,
            'advisory_id' => $this->advisoryId,
            'title' => $this->title,
            'severity' => $this->severity->value,
            'link' => $this->link,
            'cve' => $this->cve,
            'fixed_in' => $this->fixedIn,
            'affected_versions' => $this->affectedVersions,
            'reported_at' => $this->reportedAt,
            'exploited' => $this->isExploited(),
            'kev' => $this->exploited?->toArray(),
            'aliases' => $this->aliases,
            'links' => $this->links,
            'meta' => $this->metadata,
        ];
    }

    /**
     * @return list<string>
     */
    private static function strings(mixed $value): array
    {
        return is_array($value) ? array_values(array_filter($value, fn (mixed $item): bool => is_string($item) && $item !== '')) : [];
    }

    /**
     * @return array<string, scalar>
     */
    private static function scalars(mixed $value): array
    {
        return is_array($value) ? array_filter($value, fn (mixed $item, mixed $key): bool => is_string($key) && is_scalar($item), ARRAY_FILTER_USE_BOTH) : [];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
