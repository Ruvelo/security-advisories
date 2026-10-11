<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * What a new report changed against what an adapter already knew: the news.
 */
final readonly class Changes
{
    /**
     * @param list<Finding> $new Findings not known before (or known, then resolved, and back again)
     * @param list<Finding> $exploited Findings that are exploited now and weren't before; includes new ones that arrive exploited
     * @param list<string> $resolved Keys that are gone: the package was updated or the advisory withdrawn
     */
    public function __construct(
        public array $new = [],
        public array $exploited = [],
        public array $resolved = [],
    ) {
    }

    public function isEmpty(): bool
    {
        return $this->new === [] && $this->exploited === [] && $this->resolved === [];
    }
}
