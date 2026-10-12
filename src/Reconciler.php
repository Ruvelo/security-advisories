<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * Compares a report with what was known before, so only what changed is news.
 *
 * It stores nothing: the adapter keeps the known set wherever it likes (a
 * table, a cache, a file) as finding key => was exploited, and passes it in.
 * The key is Finding::key().
 *
 * To say more than a key when something is resolved, keep lastSeen() beside
 * the known set and pass it to reconcile(): Changes::$resolvedFindings then
 * holds what each resolved finding was.
 */
final class Reconciler
{
    /**
     * @param array<string, bool> $known Finding key => whether it was exploited when last seen
     * @param array<string, Finding|array<mixed>> $lastSeen Finding key => the finding when last seen (a Finding or its toArray()), as lastSeen() gave
     */
    public function reconcile(array $known, Report $report, array $lastSeen = []): Changes
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

        $resolved = $this->resolved($known, $present, $report);
        $resolvedFindings = [];

        foreach ($resolved as $key) {
            $data = $lastSeen[$key] ?? null;
            $finding = $data instanceof Finding ? $data : (is_array($data) ? Finding::fromArray($data) : null);

            if ($finding !== null) {
                $resolvedFindings[$key] = $finding;
            }
        }

        return new Changes($new, $exploited, $resolved, $resolvedFindings);
    }

    /**
     * The known set after this report: what to store for the next check.
     * Exploited stays exploited, resolved keys are dropped, and anything the
     * report couldn't vouch for is kept as it was.
     *
     * Keys in $unacknowledged are left exactly as they were in $known: an
     * alert that couldn't be delivered is then news again next time (new,
     * newly exploited or resolved, whichever it was).
     *
     * @param array<string, bool> $known
     * @param list<string>|array<string, mixed> $unacknowledged Finding keys (as a list, or as array keys)
     * @return array<string, bool>
     */
    public function next(array $known, Report $report, array $unacknowledged = []): array
    {
        $next = $known;

        foreach ($this->resolved($known, array_fill_keys(array_map(fn (Finding $f): string => $f->key(), $report->findings), true), $report) as $key) {
            unset($next[$key]);
        }

        foreach ($report->findings as $finding) {
            $next[$finding->key()] = $finding->isExploited() || ($known[$finding->key()] ?? false);
        }

        foreach (self::keys($unacknowledged) as $key) {
            if (array_key_exists($key, $known)) {
                $next[$key] = $known[$key];
            } else {
                unset($next[$key]);
            }
        }

        return $next;
    }

    /**
     * The finding data to keep beside next(): for every key in it, the
     * finding as this report has it, or as it was last seen when this report
     * couldn't vouch for it. Store it and pass it to the next reconcile().
     *
     * @param array<string, Finding|array<mixed>> $lastSeen What the previous call gave
     * @param array<string, bool> $next What next() gave
     * @return array<string, array<string, mixed>> Finding key => Finding::toArray()
     */
    public function lastSeen(array $lastSeen, Report $report, array $next): array
    {
        $current = [];
        foreach ($report->findings as $finding) {
            $current[$finding->key()] = $finding->toArray();
        }

        $out = [];
        foreach (array_keys($next) as $key) {
            $data = $current[$key] ?? $lastSeen[$key] ?? null;

            if ($data instanceof Finding) {
                $data = $data->toArray();
            }

            if (is_array($data)) {
                $out[$key] = $data;
            }
        }

        return $out;
    }

    /**
     * @param array<mixed> $keys
     * @return list<string>
     */
    private static function keys(array $keys): array
    {
        return array_values(array_filter(array_is_list($keys) ? $keys : array_keys($keys), 'is_string'));
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
