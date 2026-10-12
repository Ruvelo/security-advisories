<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;

/**
 * Collapses the same vulnerability arriving from several sources into one
 * match: same package, and the same id, CVE or an overlapping alias.
 *
 * The match from the source with exact ranges (an affected-versions
 * constraint) wins, then the one that names a fix; aliases and links of the
 * others are merged in, and "exploited" is kept if any of them has it.
 * The Scanner runs this after every source has answered.
 */
final class MatchMerger
{
    /**
     * @param list<AdvisoryMatch> $matches
     * @return list<AdvisoryMatch> In order of first appearance
     */
    public static function merge(array $matches): array
    {
        /** @var array<string, list<array<string, true>>> $groupIds Per package: the identifiers of each group */
        $groupIds = [];
        /** @var array<string, list<list<AdvisoryMatch>>> $groupMatches */
        $groupMatches = [];

        foreach ($matches as $match) {
            $bucket = $match->advisory->ecosystem->value.':'.strtolower($match->package->name);
            $ids = array_fill_keys(self::identifiers($match->advisory), true);
            $into = null;

            foreach ($groupIds[$bucket] ?? [] as $i => $known) {
                if (array_intersect_key($known, $ids) === []) {
                    continue;
                }

                if ($into === null) {
                    $into = $i;
                    $groupIds[$bucket][$i] += $ids;
                    $groupMatches[$bucket][$i][] = $match;
                } else {
                    // This match bridges two groups: join them.
                    $groupIds[$bucket][$into] += $known;
                    array_push($groupMatches[$bucket][$into], ...$groupMatches[$bucket][$i]);
                    unset($groupIds[$bucket][$i], $groupMatches[$bucket][$i]);
                }
            }

            if ($into === null) {
                $groupIds[$bucket][] = $ids;
                $groupMatches[$bucket][] = [$match];
            }
        }

        $merged = [];
        foreach ($groupMatches as $groups) {
            foreach ($groups as $group) {
                if ($group !== []) {
                    $merged[] = self::combine($group);
                }
            }
        }

        return $merged;
    }

    /**
     * Every CVE the advisory is known by.
     *
     * @return list<string> Upper case
     */
    public static function cves(Advisory $advisory): array
    {
        return array_values(array_unique(array_filter(
            array_map('strtoupper', [...($advisory->cve !== null ? [$advisory->cve] : []), $advisory->id, ...$advisory->aliases]),
            fn (string $id): bool => preg_match('/^CVE-\d{4}-\d+$/', $id) === 1,
        )));
    }

    /**
     * @return list<string> Upper case
     */
    private static function identifiers(Advisory $advisory): array
    {
        return array_values(array_unique(array_map('strtoupper', array_filter(
            [$advisory->id, $advisory->cve, ...$advisory->aliases],
            fn (?string $id): bool => $id !== null && $id !== '',
        ))));
    }

    /**
     * @param non-empty-list<AdvisoryMatch> $group
     */
    private static function combine(array $group): AdvisoryMatch
    {
        if (count($group) === 1) {
            return $group[0];
        }

        // Stable: the earlier source wins a tie.
        $ranked = $group;
        usort($ranked, fn (AdvisoryMatch $a, AdvisoryMatch $b): int => [$b->advisory->hasExactRanges(), ($b->fixedIn ?? $b->advisory->fixedIn) !== null]
            <=> [$a->advisory->hasExactRanges(), ($a->fixedIn ?? $a->advisory->fixedIn) !== null]
            ?: array_search($a, $group, true) <=> array_search($b, $group, true));

        $winner = $ranked[0];
        $first = $winner->advisory;
        $others = array_slice($ranked, 1);

        $kev = null;
        $allKnown = true;
        foreach ($ranked as $match) {
            $kev ??= $match->advisory->kev;
            $allKnown = $allKnown && $match->advisory->kevKnown;
        }

        $severity = $first->severity;
        foreach ($others as $match) {
            if ($match->advisory->severity->rank() > $severity->rank()) {
                $severity = $match->advisory->severity;
            }
        }

        $aliases = [];
        $links = $first->links;
        foreach ($ranked as $i => $match) {
            foreach ([$match->advisory->id, $match->advisory->cve, ...$match->advisory->aliases] as $id) {
                if ($id !== null && $id !== '') {
                    $aliases[strtoupper($id)] ??= $id;
                }
            }

            if ($i > 0) {
                array_push($links, ...($match->advisory->link !== null ? [$match->advisory->link] : []), ...$match->advisory->links);
            }
        }
        unset($aliases[strtoupper($first->id)]);

        $cve = $first->cve ?? self::cves($first)[0] ?? null;
        foreach ($others as $match) {
            $cve ??= $match->advisory->cve ?? self::cves($match->advisory)[0] ?? null;
        }

        $fixedIn = $winner->fixedIn ?? $first->fixedIn;
        $reportedAt = $first->reportedAt;
        $link = $first->link;
        foreach ($others as $match) {
            if ($fixedIn === null && $match->package->version === $winner->package->version) {
                $fixedIn = $match->fixedIn ?? $match->advisory->fixedIn;
            }
            $reportedAt ??= $match->advisory->reportedAt;
            $link ??= $match->advisory->link;
        }

        $links = array_values(array_unique(array_filter($links, fn (string $other): bool => $other !== $link)));

        $advisory = new Advisory(
            id: $first->id,
            ecosystem: $first->ecosystem,
            package: $first->package,
            title: $first->title,
            link: $link,
            cve: $cve,
            severity: $severity,
            affectedVersions: $first->affectedVersions,
            fixedIn: $first->fixedIn,
            reportedAt: $reportedAt,
            kev: $kev,
            kevKnown: $kev !== null || $allKnown,
            aliases: array_values($aliases),
            links: $links,
        );

        return new AdvisoryMatch($winner->package, $advisory, $fixedIn);
    }
}
