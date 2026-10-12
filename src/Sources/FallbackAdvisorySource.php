<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Note;

/**
 * Asks one source first and, for any ecosystem it can't answer in full
 * (unreachable, too slow, a bad signature, stale data), asks the fallbacks
 * instead. Each ecosystem gets one complete answer, never half of each.
 *
 * The default chain is Valtry first, then Packagist and OSV directly.
 */
final class FallbackAdvisorySource implements AdvisorySource, ReportsOrigin, EmitsNotes
{
    /** @var array<string, string> Ecosystem value => origin */
    private array $origins = [];

    /** @var array<string, string> Ecosystem value => why the primary wasn't used */
    private array $reasons = [];

    /** @var list<Note> */
    private array $notes = [];

    /**
     * @param list<AdvisorySource> $fallbacks
     */
    public function __construct(
        private readonly AdvisorySource $primary,
        private readonly array $fallbacks,
        private readonly string $primaryOrigin = 'valtry',
        private readonly string $fallbackOrigin = 'public',
    ) {
    }

    public function supports(Ecosystem $ecosystem): bool
    {
        if ($this->primary->supports($ecosystem)) {
            return true;
        }

        foreach ($this->fallbacks as $fallback) {
            if ($fallback->supports($ecosystem)) {
                return true;
            }
        }

        return false;
    }

    public function find(array $packages, bool $fresh = false): array
    {
        $byEcosystem = [];
        foreach ($packages as $package) {
            $byEcosystem[$package->ecosystem->value][] = $package;
        }

        $this->notes = [];
        $matches = [];
        foreach ($byEcosystem as $value => $group) {
            array_push($matches, ...$this->findFor(Ecosystem::from($value), $group, $fresh));
        }

        return $matches;
    }

    /**
     * The notes of whichever sources answered the last find().
     *
     * @return list<Note>
     */
    public function notes(): array
    {
        return $this->notes;
    }

    public function origin(Ecosystem $ecosystem): ?string
    {
        return $this->origins[$ecosystem->value] ?? null;
    }

    /**
     * Why the primary source didn't answer for this ecosystem, if it didn't.
     */
    public function reason(Ecosystem $ecosystem): ?string
    {
        return $this->reasons[$ecosystem->value] ?? null;
    }

    /**
     * @param list<InstalledPackage> $packages
     * @return list<AdvisoryMatch>
     *
     * @throws SourceUnavailable When a fallback can't answer either
     */
    private function findFor(Ecosystem $ecosystem, array $packages, bool $fresh): array
    {
        unset($this->origins[$ecosystem->value], $this->reasons[$ecosystem->value]);

        $failure = null;

        if ($this->primary->supports($ecosystem)) {
            try {
                $matches = $this->primary->find($packages, $fresh);
                $this->collect($this->primary);
                $this->origins[$ecosystem->value] = $this->primaryOrigin;

                return $matches;
            } catch (SourceUnavailable $e) {
                $failure = $e;
                $this->reasons[$ecosystem->value] = $e->getMessage();
            }
        }

        $fallbacks = array_values(array_filter($this->fallbacks, fn (AdvisorySource $source): bool => $source->supports($ecosystem)));

        // Nothing to fall back to: an empty answer would look like a clean one.
        if ($fallbacks === []) {
            throw $failure ?? SourceUnavailable::because('Advisories', 'no source covers '.$ecosystem->label().' packages');
        }

        $this->origins[$ecosystem->value] = $this->fallbackOrigin;
        $matches = [];

        foreach ($fallbacks as $fallback) {
            array_push($matches, ...$fallback->find($packages, $fresh));
            $this->collect($fallback);
        }

        return $matches;
    }

    private function collect(AdvisorySource $source): void
    {
        if ($source instanceof EmitsNotes) {
            array_push($this->notes, ...$source->notes());
        }
    }
}
