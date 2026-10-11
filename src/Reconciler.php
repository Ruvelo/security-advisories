<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * Compares a report with what was known before, so only what changed is news.
 *
 * It stores nothing: the adapter keeps the known set wherever it likes (a
 * table, a cache, a file) as finding key => was exploited, and passes it in.
 * The key is Finding::key().
 */
final class Reconciler
{
    /**
     * @param array<string, bool> $known Finding key => whether it was exploited when last seen
     */
    public function reconcile(array $known, Report $report): Changes
    {
        $new = [];
        $exploited = [];
        $present = [];

        foreach ($report->findings as $finding) {
            $key = $finding->key();
            $present[$key] = true;

            if (! array_key_exists($key, $known)) {
                $new[] = $finding;
            }

            // Once exploited, always exploited: an unreachable CISA feed must not lower the alarm,
            // and it only counts as news when it flips from not exploited to exploited.
            if ($finding->isExploited() && ($known[$key] ?? false) === false) {
                $exploited[] = $finding;
            }
        }

        return new Changes($new, $exploited, $this->resolved($known, $present, $report));
    }

    /**
     * The known set after this report: what to store for the next check.
     * Exploited stays exploited, resolved keys are dropped, and anything the
     * report couldn't vouch for is kept as it was.
     *
     * @param array<string, bool> $known
     * @return array<string, bool>
     */
    public function next(array $known, Report $report): array
    {
        $next = $known;

        foreach ($this->resolved($known, array_fill_keys(array_map(fn (Finding $f): string => $f->key(), $report->findings), true), $report) as $key) {
            unset($next[$key]);
        }

        foreach ($report->findings as $finding) {
            $next[$finding->key()] = $finding->isExploited() || ($known[$finding->key()] ?? false);
        }

        return $next;
    }

    /**
     * Only a complete report can say something is gone, and only for the
     * ecosystems it checked: a failed feed or a missing lockfile never
     * resolves anything.
     *
     * @param array<string, bool> $known
     * @param array<string, true> $present
     * @return list<string>
     */
    private function resolved(array $known, array $present, Report $report): array
    {
        if (! $report->isComplete()) {
            return [];
        }

        $resolved = [];

        foreach (array_keys($known) as $key) {
            if (isset($present[$key])) {
                continue;
            }

            $ecosystem = Ecosystem::tryFrom(explode(':', $key, 2)[0]);

            if ($ecosystem !== null && $report->isCheckedFor($ecosystem)) {
                $resolved[] = $key;
            }
        }

        return $resolved;
    }
}
