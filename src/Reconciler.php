<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * Compares a report with what was known before, so only what changed is news.
 *
 * It stores nothing: the adapter keeps the known set wherever it likes (a
 * table, a cache, a file) as finding key => was exploited, and passes it in.
 * The key is Finding::key(), and a finding also counts as known when any of
 * its Finding::altKeys() is: the same vulnerability reported under another id
 * (a different source won the dedupe this time) is not news, and its old
 * entry is not "resolved". For that to work from a known key alone the other
 * way round too (the stored entry has the old id, the new finding only knows
 * the CVE), pass lastSeen() as well: the old finding's own aliases and CVE
 * are matched against the new ones.
 *
 * next() keeps the key a finding was first stored under, so the stored
 * identity never churns when the winning id does.
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
        $index = $this->index($known, $lastSeen);

        foreach ($report->findings as $finding) {
            $matched = $this->matches($index, $finding);

            if ($matched === []) {
                $new[] = $finding;
            }

            // Once exploited, always exploited: an unreachable CISA feed must not lower the alarm,
            // and it only counts as news when it flips from not exploited to exploited.
            if ($finding->isExploited() && ! $this->anyExploited($known, $matched)) {
                $exploited[] = $finding;
            }
        }

        $resolved = $this->resolved($known, $report, $lastSeen);
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
     * A finding already known under another key (see Finding::altKeys()) keeps
     * the stored key; only a finding that is new is stored under its own key().
     *
     * @param array<string, bool> $known
     * @param list<string>|array<string, mixed> $unacknowledged Finding keys (as a list, or as array keys), stored or current
     * @param array<string, Finding|array<mixed>> $lastSeen What lastSeen() gave last time; lets an entry be recognised by the CVE and aliases it had
     * @return array<string, bool>
     */
    public function next(array $known, Report $report, array $unacknowledged = [], array $lastSeen = []): array
    {
        $next = $known;
        $index = $this->index($known, $lastSeen);

        foreach ($this->resolved($known, $report, $lastSeen) as $key) {
            unset($next[$key]);
        }

        $stored = [];
        foreach ($report->findings as $finding) {
            $matched = $this->matches($index, $finding);
            $key = $matched[0] ?? $finding->key();
            $stored[$finding->key()] = $key;

            $next[$key] = $finding->isExploited() || $this->anyExploited($known, $matched);

            // Several old entries for one vulnerability collapse into the first.
            foreach (array_slice($matched, 1) as $duplicate) {
                unset($next[$duplicate]);
            }
        }

        foreach (self::keys($unacknowledged) as $key) {
            $key = array_key_exists($key, $known) ? $key : ($stored[$key] ?? $key);

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
        $index = $this->index($next, $lastSeen);
        $current = [];
        foreach ($report->findings as $finding) {
            $current[$this->matches($index, $finding)[0] ?? $finding->key()] = $finding->toArray();
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
     * Known entries by every name they go by: the key itself, then (from
     * lastSeen) the keys of the finding it was.
     *
     * @param array<string, bool> $known
     * @param array<string, Finding|array<mixed>> $lastSeen
     * @return array{exact: array<string, string>, alt: array<string, list<string>>}
     */
    private function index(array $known, array $lastSeen): array
    {
        $exact = [];
        $alt = [];

        foreach (array_keys($known) as $key) {
            $exact[$key] = $key;
            $data = $lastSeen[$key] ?? null;
            $old = $data instanceof Finding ? $data : (is_array($data) ? Finding::fromArray($data) : null);

            foreach ($old === null ? [] : [$old->key(), ...$old->altKeys()] as $name) {
                $alt[$name][] = $key;
            }
        }

        return ['exact' => $exact, 'alt' => $alt];
    }

    /**
     * The known keys this finding is: its own key() first, then those that
     * share one of its alt keys.
     *
     * @param array{exact: array<string, string>, alt: array<string, list<string>>} $index
     * @return list<string>
     */
    private function matches(array $index, Finding $finding): array
    {
        $found = [];

        foreach ([$finding->key(), ...$finding->altKeys()] as $name) {
            if (isset($index['exact'][$name])) {
                $found[$name] = true;
            }
        }
        foreach ([$finding->key(), ...$finding->altKeys()] as $name) {
            foreach ($index['alt'][$name] ?? [] as $key) {
                $found[$key] = true;
            }
        }

        return array_keys($found);
    }

    /**
     * @param array<string, bool> $known
     * @param list<string> $keys
     */
    private function anyExploited(array $known, array $keys): bool
    {
        foreach ($keys as $key) {
            if (($known[$key] ?? false) === true) {
                return true;
            }
        }

        return false;
    }

    /**
     * Only a complete report can say something is gone, and only for the
     * ecosystems it checked: a failed feed or a missing lockfile never
     * resolves anything. An entry matched by any current finding's key or
     * alt key is not gone.
     *
     * @param array<string, bool> $known
     * @param array<string, Finding|array<mixed>> $lastSeen
     * @return list<string>
     */
    private function resolved(array $known, Report $report, array $lastSeen = []): array
    {
        if (! $report->isComplete()) {
            return [];
        }

        $index = $this->index($known, $lastSeen);
        $present = [];
        foreach ($report->findings as $finding) {
            foreach ($this->matches($index, $finding) as $key) {
                $present[$key] = true;
            }
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
