<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Support;

use Closure;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Note;
use Ruvelo\SecurityAdvisories\Sources\AdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\EmitsNotes;

/**
 * An advisory source that answers with what the test hands it.
 */
final class StubSource implements AdvisorySource, EmitsNotes
{
    /**
     * @param list<Ecosystem> $ecosystems
     * @param Closure(list<\Ruvelo\SecurityAdvisories\InstalledPackage>): list<AdvisoryMatch> $answer
     * @param list<Note> $notes
     */
    public function __construct(private readonly array $ecosystems, private readonly Closure $answer, private readonly array $notes = [])
    {
    }

    public function supports(Ecosystem $ecosystem): bool
    {
        return in_array($ecosystem, $this->ecosystems, true);
    }

    public function find(array $packages, bool $fresh = false): array
    {
        return ($this->answer)($packages);
    }

    public function notes(): array
    {
        return $this->notes;
    }
}
