<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Ruvelo\SecurityAdvisories\Packages\PackageSource;
use Ruvelo\SecurityAdvisories\Sources\AdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\ExploitCatalogue;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;

/**
 * Reads the package lists, asks the advisory sources about the installed
 * versions and marks what's exploited in the wild. It changes nothing and
 * never throws for a feed or a file: what couldn't be checked ends up in
 * Report::$problems.
 */
final class Scanner
{
    /**
     * @param list<PackageSource> $packageSources
     * @param list<AdvisorySource> $advisorySources
     */
    public function __construct(
        private readonly array $packageSources,
        private readonly array $advisorySources,
        private readonly ?ExploitCatalogue $exploits = null,
    ) {
    }

    /**
     * The usual setup for a project directory: composer.lock through
     * Packagist, package-lock.json (if there is one) through OSV, and CISA KEV.
     * Pass a client and a cache to use the platform's own.
     */
    public static function forProject(string $directory, ?JsonClient $http = null, ?CacheInterface $cache = null, bool $includeDev = true, Ttls $ttls = new Ttls()): self
    {
        $http ??= new JsonClient();
        $responses = new ResponseCache($cache, $ttls);
        $directory = rtrim($directory, '/\\');

        return new self(
            [new ComposerLockReader($directory.'/composer.lock', $includeDev), new NpmLockReader($directory.'/package-lock.json', $includeDev)],
            [new PackagistAdvisorySource($http, $responses), new OsvSource($http, $responses)],
            new KevCatalogue($http, $responses),
        );
    }

    /**
     * @param bool $fresh Skip any cache
     */
    public function scan(bool $fresh = false): Report
    {
        $problems = [];
        $lists = $this->read($problems);

        $counts = [];
        $checked = [];
        $matches = [];

        foreach ($lists as $ecosystem => $packages) {
            $ecosystem = Ecosystem::from($ecosystem);
            $counts[$ecosystem->value] = count($packages);
            $sources = array_values(array_filter($this->advisorySources, fn (AdvisorySource $source): bool => $source->supports($ecosystem)));

            if ($sources === []) {
                $problems[] = "No advisory source covers {$ecosystem->label()} packages, so they weren't checked.";

                continue;
            }

            $complete = true;
            foreach ($sources as $source) {
                try {
                    array_push($matches, ...$source->find($packages, $fresh));
                } catch (SourceUnavailable $e) {
                    $problems[] = $e->getMessage()." {$this->capitalised($ecosystem)} packages weren't checked.";
                    $complete = false;
                }
            }

            if ($complete) {
                $checked[] = $ecosystem;
            }
        }

        $exploited = [];
        $kevChecked = false;

        if ($this->exploits !== null) {
            try {
                $cves = array_values(array_unique(array_filter(array_map(fn (AdvisoryMatch $m): ?string => $m->advisory->cve, $matches))));
                $exploited = $this->exploits->lookup($cves, $fresh);
                $kevChecked = true;
            } catch (SourceUnavailable $e) {
                $problems[] = $e->getMessage()." Findings aren't marked as exploited this time.";
            }
        }

        $findings = [];
        foreach ($matches as $match) {
            $finding = Finding::from($match, $match->advisory->cve !== null ? ($exploited[strtoupper($match->advisory->cve)] ?? null) : null);

            // The same advisory can match two installed copies (npm): report it once.
            $findings[$finding->key()] ??= $finding;
        }

        return new Report(array_values($findings), $counts, $checked, $problems, $kevChecked, new DateTimeImmutable());
    }

    /**
     * @param list<string> $problems
     * @return array<string, list<InstalledPackage>> Package lists by ecosystem value; ecosystems that couldn't be read are left out
     */
    private function read(array &$problems): array
    {
        $lists = [];

        foreach ($this->packageSources as $source) {
            try {
                $packages = $source->packages();
            } catch (PackagesUnreadable $e) {
                $problems[] = $e->getMessage()." {$this->capitalised($source->ecosystem())} packages weren't checked.";

                continue;
            }

            if ($packages === null) {
                if ($source->isRequired()) {
                    $problems[] = "Couldn't find {$source->describe()}, so {$source->ecosystem()->label()} packages weren't checked.";
                }

                continue;
            }

            $lists[$source->ecosystem()->value] = [...($lists[$source->ecosystem()->value] ?? []), ...$packages];
        }

        return $lists;
    }

    private function capitalised(Ecosystem $ecosystem): string
    {
        return ucfirst($ecosystem->label());
    }
}
