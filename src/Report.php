<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

use DateTimeImmutable;
use DateTimeInterface;
use JsonSerializable;

/**
 * The result of a scan: every finding, worst first, and what was checked.
 *
 * A report with no findings is only "clean" if it is also complete: look at
 * isComplete() / problems before telling anyone all is well.
 */
final readonly class Report implements JsonSerializable
{
    /** @var list<Finding> */
    public array $findings;

    /**
     * Where the advisories came from: "valtry" (Valtry's signed Advisory API),
     * "public" (Packagist, OSV and CISA KEV directly) or "mixed" when
     * ecosystems differed. See $sources for each ecosystem.
     */
    public string $source;

    /**
     * @param list<Finding> $findings
     * @param array<string, int> $packages Packages checked, by ecosystem value
     * @param list<Ecosystem> $checked Ecosystems whose advisories were fetched in full; only these can mark findings as fixed
     * @param list<string> $problems What couldn't be checked, in plain words
     * @param bool $kevChecked Whether the exploited-in-the-wild catalogue was read
     * @param array<string, string> $sources Which path answered each ecosystem (value => "valtry" or "public"), when the advisory source says
     */
    public function __construct(
        array $findings,
        public array $packages = [],
        public array $checked = [],
        public array $problems = [],
        public bool $kevChecked = true,
        public ?DateTimeImmutable $checkedAt = null,
        public array $sources = [],
    ) {
        usort($findings, Finding::compare(...));
        $this->findings = $findings;

        $paths = array_values(array_unique($sources));
        $this->source = match (true) {
            $paths === [] => 'public',
            count($paths) === 1 => $paths[0],
            default => 'mixed',
        };
    }

    public function isClean(): bool
    {
        return $this->findings === [];
    }

    /**
     * False when a lockfile, a feed or the exploited catalogue couldn't be read.
     */
    public function isComplete(): bool
    {
        return $this->problems === [];
    }

    public function isCheckedFor(Ecosystem $ecosystem): bool
    {
        return in_array($ecosystem, $this->checked, true);
    }

    /**
     * The worst finding: exploited first, then the highest severity.
     */
    public function worst(): ?Finding
    {
        return $this->findings[0] ?? null;
    }

    /**
     * @return list<Finding>
     */
    public function exploited(): array
    {
        return array_values(array_filter($this->findings, fn (Finding $finding): bool => $finding->isExploited()));
    }

    /**
     * @return list<Finding> Findings that meet the threshold
     */
    public function failing(Threshold $threshold): array
    {
        return array_values(array_filter($this->findings, fn (Finding $finding): bool => $threshold->isMetBy($finding)));
    }

    /**
     * Whether a CI step or health check should fail. Based on findings only:
     * pair it with isComplete() to treat an incomplete check as a failure too.
     */
    public function failsOn(Threshold $threshold): bool
    {
        return $this->failing($threshold) !== [];
    }

    public function packageCount(?Ecosystem $ecosystem = null): int
    {
        return $ecosystem === null ? array_sum($this->packages) : ($this->packages[$ecosystem->value] ?? 0);
    }

    /**
     * Counts for a one-line summary: exploited first, then each severity
     * among the rest. Zero counts are left out.
     *
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = ['exploited' => 0];
        foreach (Severity::cases() as $severity) {
            $counts[$severity->value] = 0;
        }

        foreach ($this->findings as $finding) {
            $counts[$finding->isExploited() ? 'exploited' : $finding->severity->value]++;
        }

        return array_filter($counts);
    }

    /**
     * @return list<string> Affected package names, worst first, each once
     */
    public function affectedPackages(): array
    {
        return array_values(array_unique(array_map(fn (Finding $finding): string => $finding->package, $this->findings)));
    }

    /**
     * @return array{checked_at: string|null, clean: bool, complete: bool, kev_checked: bool, source: string, sources: array<string, string>, packages: array<string, int>, checked: list<string>, counts: array<string, int>, problems: list<string>, findings: list<array<string, mixed>>}
     */
    public function toArray(): array
    {
        return [
            'checked_at' => $this->checkedAt?->format(DateTimeInterface::ATOM),
            'clean' => $this->isClean(),
            'complete' => $this->isComplete(),
            'kev_checked' => $this->kevChecked,
            'source' => $this->source,
            'sources' => $this->sources,
            'packages' => $this->packages,
            'checked' => array_map(fn (Ecosystem $ecosystem): string => $ecosystem->value, $this->checked),
            'counts' => $this->counts(),
            'problems' => $this->problems,
            'findings' => array_map(fn (Finding $finding): array => $finding->toArray(), $this->findings),
        ];
    }

    /**
     * @return array<string, mixed>
     */
    public function jsonSerialize(): array
    {
        return $this->toArray();
    }
}
