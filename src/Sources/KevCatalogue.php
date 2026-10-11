<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\KevEntry;

/**
 * CISA's Known Exploited Vulnerabilities catalogue: CVEs attackers are
 * using in the wild right now. Nothing is sent; the whole list is
 * downloaded (and cached).
 */
final class KevCatalogue implements ExploitCatalogue
{
    public const URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    private readonly JsonClient $http;
    private readonly ResponseCache $cache;

    public function __construct(?JsonClient $http = null, ?ResponseCache $cache = null, private readonly string $url = self::URL)
    {
        $this->http = $http ?? new JsonClient();
        $this->cache = $cache ?? new ResponseCache();
    }

    public function lookup(array $cves, bool $fresh = false): array
    {
        if ($cves === []) {
            return [];
        }

        $catalogue = $this->catalogue($fresh);
        $found = [];

        foreach ($cves as $cve) {
            $cve = strtoupper($cve);
            $row = $catalogue[$cve] ?? null;

            if (is_array($row) && ($entry = KevEntry::fromArray($row)) !== null) {
                $found[$cve] = $entry;
            }
        }

        return $found;
    }

    /**
     * The catalogue, trimmed to what the alerts use, keyed by CVE.
     *
     * @return array<mixed>
     */
    public function catalogue(bool $fresh = false): array
    {
        return $this->cache->remember('kev', $this->cache->ttls->kev, $fresh, function (): array {
            $items = $this->http->get('CISA KEV', $this->url)['vulnerabilities'] ?? null;

            if (! is_array($items)) {
                throw SourceUnavailable::because('CISA KEV', 'its answer has no "vulnerabilities" list');
            }

            $catalogue = [];
            foreach ($items as $item) {
                if (is_array($item) && ($entry = KevEntry::fromCatalogue($item)) !== null) {
                    $catalogue[$entry->cve] = $entry->toArray();
                }
            }

            return $catalogue;
        });
    }
}
