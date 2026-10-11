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
 * Packagist's security advisories API: the one `composer audit` reads, fed by
 * the GitHub Advisory Database and FriendsOfPHP. Only package names are sent;
 * the versions are matched here.
 */
final class PackagistAdvisorySource implements AdvisorySource
{
    public const URL = 'https://packagist.org/api/security-advisories/';

    /** Names per request. The API takes many in one POST; this keeps bodies modest. */
    public const BATCH = 200;

    private readonly JsonClient $http;
    private readonly ResponseCache $cache;

    public function __construct(?JsonClient $http = null, ?ResponseCache $cache = null, private readonly string $url = self::URL)
    {
        $this->http = $http ?? new JsonClient();
        $this->cache = $cache ?? new ResponseCache();
    }

    public function supports(Ecosystem $ecosystem): bool
    {
        return $ecosystem === Ecosystem::Composer;
    }

    public function find(array $packages, bool $fresh = false): array
    {
        $packages = array_values(array_filter($packages, fn (InstalledPackage $p): bool => $p->ecosystem === Ecosystem::Composer));
        $byName = $this->advisories(array_map(fn (InstalledPackage $p): string => $p->name, $packages), $fresh);
        $matches = [];

        foreach ($packages as $package) {
            foreach ($byName[strtolower($package->name)] ?? [] as $advisory) {
                $constraint = (string) $advisory->affectedVersions;

                if (Versions::affects($package->version, $constraint)) {
                    $matches[] = new AdvisoryMatch($package, $advisory, Versions::fixedIn($package->version, $constraint));
                }
            }
        }

        return $matches;
    }

    /**
     * @param list<string> $names
     * @return array<string, list<Advisory>> Keyed by package name; packages without advisories are left out
     *
     * @throws SourceUnavailable
     */
    public function advisories(array $names, bool $fresh = false): array
    {
        $names = array_values(array_unique(array_map('strtolower', $names)));
        sort($names);

        $found = [];

        foreach (array_chunk($names, self::BATCH) as $batch) {
            $raw = $this->cache->remember('packagist.'.sha1(implode(',', $batch)), $this->cache->ttls->advisories, $fresh, fn (): array => $this->fetch($batch));

            foreach ($raw as $name => $list) {
                foreach (is_array($list) ? $list : [] as $item) {
                    if (($advisory = self::advisory((string) $name, $item)) !== null) {
                        $found[$advisory->package][] = $advisory;
                    }
                }
            }
        }

        return $found;
    }

    /**
     * @param list<string> $names
     * @return array<string, list<array<mixed>>>
     */
    private function fetch(array $names): array
    {
        $body = implode('&', array_map(fn (string $name): string => 'packages[]='.rawurlencode($name), $names));
        $advisories = $this->http->postForm('Packagist', $this->url, $body)['advisories'] ?? null;

        if (! is_array($advisories)) {
            throw SourceUnavailable::because('Packagist', 'its answer has no "advisories" list');
        }

        $clean = [];
        foreach ($advisories as $name => $list) {
            if (is_string($name) && is_array($list)) {
                $clean[$name] = array_values(array_filter($list, 'is_array'));
            }
        }

        return $clean;
    }

    public static function advisory(string $package, mixed $item): ?Advisory
    {
        if (! is_array($item)) {
            return null;
        }

        $id = self::string($item['advisoryId'] ?? null);
        $constraint = self::string($item['affectedVersions'] ?? null);

        if ($id === null || $constraint === null) {
            return null;
        }

        $cve = self::string($item['cve'] ?? null);
        $cve = $cve !== null && preg_match('/^CVE-\d{4}-\d+$/i', $cve) === 1 ? strtoupper($cve) : null;
        $title = self::string($item['title'] ?? null) ?? $id;

        // Some titles repeat the CVE ("CVE-2026-48736: IpUtils..."); it's shown on its own.
        if ($cve !== null && stripos($title, $cve.':') === 0) {
            $title = ltrim(substr($title, strlen($cve) + 1)) ?: $title;
        }

        return new Advisory(
            id: $id,
            ecosystem: Ecosystem::Composer,
            package: strtolower(self::string($item['packageName'] ?? null) ?? $package),
            title: $title,
            link: self::string($item['link'] ?? null),
            cve: $cve,
            severity: Severity::parse(self::string($item['severity'] ?? null)),
            affectedVersions: $constraint,
            reportedAt: self::string($item['reportedAt'] ?? null),
        );
    }

    private static function string(mixed $value): ?string
    {
        return is_string($value) && trim($value) !== '' ? trim($value) : null;
    }
}
