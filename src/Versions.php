<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

use Composer\Semver\Comparator;
use Composer\Semver\Semver;
use Composer\Semver\VersionParser;
use Throwable;

/**
 * Version arithmetic for advisories, on top of composer/semver: whether an
 * installed version is affected, and which release fixes it.
 */
final class Versions
{
    /** Hops along a chain of patch lines or minor ranges before giving up. */
    private const MAX_HOPS = 50;

    /**
     * Whether a constraint like ">=3.0.0,<3.6.4|<2.5.8" covers the version.
     * Versions or constraints Composer can't parse (a "dev-main" branch) are
     * never matched rather than guessed.
     */
    public static function affects(string $version, string $constraint): bool
    {
        if (! self::comparable($version)) {
            return false;
        }

        try {
            return Semver::satisfies($version, $constraint);
        } catch (Throwable) {
            return false;
        }
    }

    /**
     * The release that fixes the installed version, read from the constraint.
     *
     * Advisories list affected ranges, sometimes one per patch line
     * ("<2.4.4|>=2.4.4,<2.4.4-p9|>=2.4.5,<2.4.5-p8"), so a bound isn't a fix
     * if another range still covers it: this follows the upper bounds up the
     * chain until it lands on a release nothing covers. Of several ranges that
     * cover the version, the lowest bound wins.
     *
     * When the advisory only names the last affected release ("<=2.10.1"),
     * the answer is ">2.10.1". Null when it can't be told (">=1.0", "=2.4.9").
     */
    public static function fixedIn(string $version, string $constraint): ?string
    {
        if (! self::affects($version, $constraint)) {
            return null;
        }

        $groups = array_values(array_filter(
            array_map('trim', preg_split('/\s*\|\|?\s*/', $constraint) ?: []),
            fn (string $group): bool => $group !== '',
        ));
        $candidate = $version;

        for ($hop = 0; $hop < self::MAX_HOPS; $hop++) {
            $bound = null;
            $lastAffected = null;

            foreach ($groups as $group) {
                if (! self::affects($candidate, $group)) {
                    continue;
                }

                if (preg_match('/(?:^|[\s,])<(?!=)\s*v?(\d[^\s,|<>=]*)/', $group, $m) === 1 && self::comparable($m[1])) {
                    if ($bound === null || Comparator::lessThan($m[1], $bound)) {
                        $bound = $m[1];
                    }
                } elseif (preg_match('/(?:^|[\s,])<=\s*v?(\d[^\s,|<>=]*)/', $group, $m) === 1 && self::comparable($m[1])) {
                    if ($lastAffected === null || Comparator::lessThan($m[1], $lastAffected)) {
                        $lastAffected = $m[1];
                    }
                }
            }

            if ($bound === null) {
                // Only the last affected release is known: the fix is whatever came after it.
                return $lastAffected !== null ? '>'.$lastAffected : null;
            }

            if (! self::affects($bound, $constraint)) {
                return $bound;
            }

            $candidate = $bound;
        }

        return null;
    }

    /**
     * The fixing version from OSV's "affected" list: the "fixed" event of
     * the range that contains the installed version.
     *
     * @param array<mixed> $affected
     */
    public static function fixedInOsv(array $affected, string $package, string $version): ?string
    {
        if (! self::comparable($version)) {
            return null;
        }

        foreach ($affected as $entry) {
            if (! is_array($entry) || ! is_array($entry['package'] ?? null) || ($entry['package']['name'] ?? null) !== $package || ! is_array($entry['ranges'] ?? null)) {
                continue;
            }

            foreach ($entry['ranges'] as $range) {
                if (! is_array($range) || ! in_array($range['type'] ?? null, ['SEMVER', 'ECOSYSTEM'], true) || ! is_array($range['events'] ?? null)) {
                    continue;
                }

                $introduced = null;

                foreach ($range['events'] as $event) {
                    if (! is_array($event)) {
                        continue;
                    }

                    if (is_string($event['introduced'] ?? null)) {
                        $introduced = $event['introduced'];
                    } elseif (is_string($event['fixed'] ?? null) && $introduced !== null) {
                        if (self::between($version, $introduced, $event['fixed'])) {
                            return $event['fixed'];
                        }
                        $introduced = null;
                    }
                }
            }
        }

        return null;
    }

    public static function comparable(string $version): bool
    {
        try {
            (new VersionParser())->normalize($version);
        } catch (Throwable) {
            return false;
        }

        return ! str_starts_with(strtolower($version), 'dev-') && ! str_ends_with(strtolower($version), '-dev');
    }

    private static function between(string $version, string $introduced, string $fixed): bool
    {
        if (! self::comparable($fixed) || ($introduced !== '0' && ! self::comparable($introduced))) {
            return false;
        }

        return ($introduced === '0' || Comparator::greaterThanOrEqualTo($version, $introduced))
            && Comparator::lessThan($version, $fixed);
    }
}
