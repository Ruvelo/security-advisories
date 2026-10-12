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
use Ruvelo\SecurityAdvisories\Sources\EmitsNotes;
use Ruvelo\SecurityAdvisories\Sources\ExploitCatalogue;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\MatchMerger;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\ReportsOrigin;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

/**
 * Reads the package lists, asks the advisory sources about the installed
 * versions and marks what's exploited in the wild. It changes nothing and
 * never throws for a feed or a file: what couldn't be checked ends up in
 * Report::$problems.
 */
final class Scanner
{
    /** Valtry first, the public feeds when it can't answer. */
    public const SOURCE_VALTRY = 'valtry';

    /** Packagist, OSV and CISA KEV directly: nothing is sent to Valtry. */
    public const SOURCE_PUBLIC = 'public';

    /** Set to "public" to keep every scan off Valtry, whatever the code passes. */
    public const ENV = 'RUVELO_ADVISORIES_SOURCE';

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
     * The usual setup for a project directory: composer.lock and
     * package-lock.json (if there is one), checked through Valtry's signed
     * Advisory API (names only), with Packagist, OSV and CISA KEV directly
     * whenever Valtry can't answer. Pass a client and a cache to use the
     * platform's own.
     *
     * @param string|null $source "valtry" (the default) or "public" to never contact Valtry; the RUVELO_ADVISORIES_SOURCE environment variable set to "public" wins over both
     * @param string $valtryUrl Where Valtry's Advisory API lives
     * @param list<Ecosystem>|null $ecosystems Which of Composer and npm to read and check; null (the default) means both. Ecosystem::Extension has nothing built in: supply it through the two lists below
     * @param list<AdvisorySource> $extraSources Further advisory sources, asked besides the built-in ones (an adapter's own feed)
     * @param list<PackageSource> $extraPackageSources Further package lists, read besides the built-in lockfiles (an ExtensionList)
     */
    public static function forProject(
        string $directory,
        ?JsonClient $http = null,
        ?CacheInterface $cache = null,
        bool $includeDev = true,
        Ttls $ttls = new Ttls(),
        ?string $source = null,
        string $valtryUrl = ValtryAdvisorySource::URL,
        ?array $ecosystems = null,
        array $extraSources = [],
        array $extraPackageSources = [],
        ?ExploitCatalogue $exploits = null,
    ): self {
        $http ??= new JsonClient();
        $responses = new ResponseCache($cache, $ttls);
        $directory = rtrim($directory, '/\\');
        $wanted = fn (Ecosystem $ecosystem): bool => $ecosystems === null || in_array($ecosystem, $ecosystems, true);

        $public = [];
        $readers = [];
        if ($wanted(Ecosystem::Composer)) {
            $public[] = new PackagistAdvisorySource($http, $responses);
            $readers[] = new ComposerLockReader($directory.'/composer.lock', $includeDev);
        }
        if ($wanted(Ecosystem::Npm)) {
            $public[] = new OsvSource($http, $responses);
            $readers[] = new NpmLockReader($directory.'/package-lock.json', $includeDev);
        }

        $built = match (true) {
            $public === [] => [],
            self::source($source) === self::SOURCE_PUBLIC => $public,
            default => [new FallbackAdvisorySource(new ValtryAdvisorySource($http, $responses, $valtryUrl), $public)],
        };

        return new self(
            [...$readers, ...$extraPackageSources],
            [...$built, ...$extraSources],
            $exploits ?? new KevCatalogue($http, $responses),
        );
    }

    /**
     * The path to use: "public" when the environment or the caller says so, else "valtry".
     */
    public static function source(?string $requested = null): string
    {
        $env = getenv(self::ENV);
        $env = is_string($env) && $env !== '' ? $env : ($_SERVER[self::ENV] ?? $_ENV[self::ENV] ?? null);

        if (is_string($env) && strtolower(trim($env)) === self::SOURCE_PUBLIC) {
            return self::SOURCE_PUBLIC;
        }

        return $requested !== null && strtolower(trim($requested)) === self::SOURCE_PUBLIC ? self::SOURCE_PUBLIC : self::SOURCE_VALTRY;
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
        $origins = [];
        $unchecked = [];
        $notes = [];

        foreach ($lists as $ecosystem => $packages) {
            $ecosystem = Ecosystem::from($ecosystem);
            $counts[$ecosystem->value] = count($packages);
            $sources = array_values(array_filter($this->advisorySources, fn (AdvisorySource $source): bool => $source->supports($ecosystem)));

            if ($sources === []) {
                foreach ($packages as $package) {
                    $unchecked[] = new UncheckedPackage($package, "No advisory source covers {$ecosystem->label()} packages.");
                }

                continue;
            }

            $complete = true;
            foreach ($sources as $source) {
                try {
                    array_push($matches, ...$source->find($packages, $fresh));

                    if ($source instanceof EmitsNotes) {
                        array_push($notes, ...$source->notes());
                    }

                    if ($source instanceof ReportsOrigin && ($origin = $source->origin($ecosystem)) !== null) {
                        $origins[$ecosystem->value] = $origin;
                    }
                } catch (SourceUnavailable $e) {
                    $problems[] = $e->getMessage()." {$this->capitalised($ecosystem)} packages weren't checked.";
                    $complete = false;
                }
            }

            if ($complete) {
                $checked[] = $ecosystem;
            }
        }

        // The same vulnerability from two sources is one finding.
        $matches = MatchMerger::merge($matches);

        $exploited = [];
        $kevChecked = false;

        // Advisories from Valtry already carry their KEV verdict: the
        // catalogue is only downloaded for the rest.
        $unknown = array_values(array_filter($matches, fn (AdvisoryMatch $m): bool => ! $m->advisory->kevKnown));

        if ($this->exploits !== null) {
            try {
                $cves = array_values(array_unique(array_merge([], ...array_map(fn (AdvisoryMatch $m): array => MatchMerger::cves($m->advisory), $unknown))));
                $exploited = $this->exploits->lookup($cves, $fresh);
                $kevChecked = true;
            } catch (SourceUnavailable $e) {
                $problems[] = $e->getMessage()." Findings aren't marked as exploited this time.";
            }
        }

        $findings = [];
        foreach ($matches as $match) {
            $kev = $match->advisory->kev;

            if (! $match->advisory->kevKnown) {
                foreach (MatchMerger::cves($match->advisory) as $cve) {
                    $kev ??= $exploited[$cve] ?? null;
                }
            }

            $finding = Finding::from($match, $kev);

            // The same advisory can match two installed copies (npm): report it once.
            $findings[$finding->key()] ??= $finding;
        }

        return new Report(array_values($findings), $counts, $checked, $problems, $kevChecked, new DateTimeImmutable(), $origins, $unchecked, self::distinct($notes));
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

    /**
     * @param list<Note> $notes
     * @return list<Note>
     */
    private static function distinct(array $notes): array
    {
        $seen = [];
        foreach ($notes as $note) {
            $seen[json_encode($note->toArray())] ??= $note;
        }

        return array_values($seen);
    }

    private function capitalised(Ecosystem $ecosystem): string
    {
        return ucfirst($ecosystem->label());
    }
}
