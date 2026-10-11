<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Versions;

/**
 * OSV.dev, Google's open vulnerability database, for npm packages. One batch
 * query says which advisories apply to which name and version, then each
 * advisory is fetched once (and cached until it changes). Names and exact
 * versions are sent.
 */
final class OsvSource implements AdvisorySource
{
    public const URL = 'https://api.osv.dev/v1';

    /** OSV's limit per batch query. */
    public const BATCH = 1000;

    private readonly JsonClient $http;
    private readonly ResponseCache $cache;
    private readonly string $base;

    public function __construct(?JsonClient $http = null, ?ResponseCache $cache = null, string $url = self::URL)
    {
        $this->http = $http ?? new JsonClient();
        $this->cache = $cache ?? new ResponseCache();
        $this->base = rtrim($url, '/');
    }

    public function supports(Ecosystem $ecosystem): bool
    {
        return $ecosystem === Ecosystem::Npm;
    }

    public function find(array $packages, bool $fresh = false): array
    {
        $packages = array_values(array_filter($packages, fn (InstalledPackage $p): bool => $p->ecosystem === Ecosystem::Npm));
        $hits = [];

        foreach (array_chunk($packages, self::BATCH) as $batch) {
            $results = $this->cache->remember(
                'osv.'.sha1(implode(',', array_map(fn (InstalledPackage $p): string => $p->name.'@'.$p->version, $batch))),
                $this->cache->ttls->advisories,
                $fresh,
                fn (): array => $this->query($batch),
            );

            foreach ($batch as $i => $package) {
                $found = $results[$i] ?? [];

                foreach (is_array($found) ? $found : [] as $pair) {
                    if (is_array($pair) && is_string($pair[0] ?? null) && is_string($pair[1] ?? null)) {
                        $hits[] = [$package, $pair[0], $pair[1]];
                    }
                }
            }
        }

        $matches = [];
        $details = [];

        foreach ($hits as [$package, $id, $modified]) {
            // An advisory that hits several packages is fetched once.
            $details[$id.'|'.$modified] ??= $this->details($id, $modified, $fresh);
            $advisory = self::advisory($details[$id.'|'.$modified], $package);
            $matches[] = new AdvisoryMatch($package, $advisory, $advisory->fixedIn);
        }

        return $matches;
    }

    /**
     * @param list<InstalledPackage> $batch
     * @return array<int, list<array{0: string, 1: string}>> Advisory ids and modified dates, by index in the batch
     */
    private function query(array $batch): array
    {
        $queries = array_map(fn (InstalledPackage $p): array => [
            'package' => ['name' => $p->name, 'ecosystem' => 'npm'],
            'version' => $p->version,
        ], $batch);

        $results = $this->http->postJson('OSV', $this->base.'/querybatch', ['queries' => $queries])['results'] ?? null;

        if (! is_array($results)) {
            throw SourceUnavailable::because('OSV', 'its answer has no "results" list');
        }

        $ids = [];
        foreach (array_values($results) as $i => $result) {
            $vulns = is_array($result) && is_array($result['vulns'] ?? null) ? $result['vulns'] : [];

            foreach ($vulns as $vuln) {
                if (is_array($vuln) && is_string($vuln['id'] ?? null)) {
                    $ids[$i][] = [$vuln['id'], is_string($vuln['modified'] ?? null) ? $vuln['modified'] : ''];
                }
            }
        }

        return $ids;
    }

    /**
     * Cached by id and modified date, so a changed advisory is fetched again.
     *
     * @return array<mixed>
     */
    private function details(string $id, string $modified, bool $fresh): array
    {
        return $this->cache->remember(
            'osv-vuln.'.sha1($id.'|'.$modified),
            $this->cache->ttls->osvDetails,
            $fresh,
            fn (): array => $this->http->get('OSV', $this->base.'/vulns/'.rawurlencode($id)),
        );
    }

    /**
     * @param array<mixed> $vuln An OSV record
     */
    public static function advisory(array $vuln, InstalledPackage $package): Advisory
    {
        $id = is_string($vuln['id'] ?? null) ? $vuln['id'] : 'unknown';
        $aliases = array_values(array_filter(is_array($vuln['aliases'] ?? null) ? $vuln['aliases'] : [], 'is_string'));
        $cve = array_values(array_filter([$id, ...$aliases], fn (string $alias): bool => preg_match('/^CVE-\d{4}-\d+$/i', $alias) === 1))[0] ?? null;
        $ghsa = array_values(array_filter([$id, ...$aliases], fn (string $alias): bool => str_starts_with($alias, 'GHSA-')))[0] ?? null;
        $specific = is_array($vuln['database_specific'] ?? null) ? $vuln['database_specific'] : [];
        $severity = is_string($specific['severity'] ?? null) ? $specific['severity'] : null;
        $summary = is_string($vuln['summary'] ?? null) && trim($vuln['summary']) !== '' ? trim($vuln['summary']) : null;
        $affected = is_array($vuln['affected'] ?? null) ? $vuln['affected'] : [];

        return new Advisory(
            id: $id,
            ecosystem: Ecosystem::Npm,
            package: $package->name,
            title: $summary ?? $id,
            link: $ghsa !== null ? 'https://github.com/advisories/'.$ghsa : 'https://osv.dev/vulnerability/'.rawurlencode($id),
            cve: $cve !== null ? strtoupper($cve) : null,
            severity: Severity::parse($severity),
            fixedIn: Versions::fixedInOsv($affected, $package->name, $package->version),
            reportedAt: is_string($vuln['published'] ?? null) ? $vuln['published'] : null,
        );
    }
}
