<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Valtry;

use DateTimeImmutable;
use DateTimeZone;
use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\AdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Versions;
use Throwable;

/**
 * Valtry's Advisory API: Packagist, OSV and CISA KEV data, normalised and
 * signed, in one request. Composer and npm.
 *
 * Only package names are sent (POST, JSON), never versions: matching happens
 * here, with composer/semver, exactly as for the public feeds. Each answer
 * must carry a valid Ed25519 signature from a key pinned in Keys, echo the
 * request's random nonce (so an old answer can't be replayed) and cover every
 * name asked about. Anything else (no answer within 5 seconds, an error, a
 * bad signature, data Valtry itself reports as stale) is SourceUnavailable,
 * and FallbackAdvisorySource asks the public feeds instead. After a network
 * failure, an error or a bad signature, Valtry is skipped for five minutes.
 *
 * Without a pinned key (Keys still holds a placeholder) nothing is sent at
 * all: an answer that can't be verified is worthless.
 */
final class ValtryAdvisorySource implements AdvisorySource
{
    public const URL = 'https://valtry.co.uk/api/advisories/v1/query';

    /** Seconds for the whole request before falling back. */
    public const DEADLINE = 5.0;

    /** The API's limit per request. */
    public const BATCH = 1000;

    /** How long to leave Valtry alone after it failed, in seconds. */
    public const BACKOFF = 300;

    private const DOWN = 'valtry.down';

    private readonly JsonClient $http;
    private readonly ResponseCache $cache;

    /** @var array<string, non-empty-string> kid => raw public key */
    private readonly array $keys;

    /** Failed during this run: don't try again for the next ecosystem. */
    private bool $down = false;

    /**
     * @param array<string, string>|null $keys kid => base64 Ed25519 public key; the keys pinned in Keys by default
     */
    public function __construct(
        ?JsonClient $http = null,
        ?ResponseCache $cache = null,
        private readonly string $url = self::URL,
        ?array $keys = null,
        private readonly float $deadline = self::DEADLINE,
    ) {
        $this->http = ($http ?? new JsonClient())->withDeadline($deadline);
        $this->cache = $cache ?? new ResponseCache();
        $this->keys = Keys::decode($keys ?? Keys::PINNED);
    }

    public function supports(Ecosystem $ecosystem): bool
    {
        return $ecosystem === Ecosystem::Composer || $ecosystem === Ecosystem::Npm;
    }

    /**
     * Whether answers can be verified: a real key is pinned and ext-sodium is loaded.
     */
    public function isReady(): bool
    {
        return $this->keys !== [] && function_exists('sodium_crypto_sign_verify_detached');
    }

    public function find(array $packages, bool $fresh = false): array
    {
        $byEcosystem = [];
        foreach ($packages as $package) {
            if ($this->supports($package->ecosystem)) {
                $byEcosystem[$package->ecosystem->value][] = $package;
            }
        }

        $matches = [];

        foreach ($byEcosystem as $value => $group) {
            $ecosystem = Ecosystem::from($value);
            $advisories = $this->advisories($ecosystem, array_map(fn (InstalledPackage $p): string => $p->name, $group), $fresh);

            foreach ($group as $package) {
                foreach ($advisories[strtolower($package->name)] ?? [] as $item) {
                    $advisory = self::advisory($ecosystem, $package->name, $item);

                    if ($advisory === null) {
                        continue;
                    }

                    // npm advisories keep no range string (as on the public path): match on Valtry's constraint.
                    $constraint = $advisory->affectedVersions ?? $item['affected'];

                    if (Versions::affects($package->version, $constraint)) {
                        $matches[] = new AdvisoryMatch($package, $advisory, Versions::fixedIn($package->version, $constraint));
                    }
                }
            }
        }

        return $matches;
    }

    /**
     * The verified advisories for these names, as Valtry sent them.
     *
     * @param list<string> $names
     * @return array<string, list<array{id: string, affected: string}&array<string, mixed>>> Lower-case name => advisories
     *
     * @throws SourceUnavailable
     */
    public function advisories(Ecosystem $ecosystem, array $names, bool $fresh = false): array
    {
        if (! $this->isReady()) {
            throw new SourceUnavailable('Valtry', $this->keys === []
                ? 'Valtry wasn\'t used: no Valtry signing key is pinned in this build, so its answers couldn\'t be verified.'
                : 'Valtry wasn\'t used: verifying its signatures needs the sodium extension.');
        }

        if ($this->down || (! $fresh && $this->cache->get(self::DOWN, self::BACKOFF) !== null)) {
            throw new SourceUnavailable('Valtry', 'Valtry wasn\'t used: it failed a moment ago.');
        }

        $names = array_values(array_unique(array_map('strtolower', $names)));
        sort($names);
        $found = [];

        foreach (array_chunk($names, self::BATCH) as $batch) {
            $answer = $this->cache->remember(
                'valtry.'.$ecosystem->value.'.'.sha1(implode(',', $batch)),
                $this->cache->ttls->advisories,
                $fresh,
                fn (): array => $this->query($ecosystem, $batch),
            );

            foreach ($answer as $name => $items) {
                if (is_string($name) && is_array($items)) {
                    $found[$name] = array_values(array_filter($items, fn (mixed $item): bool => self::usable($item)));
                }
            }
        }

        return $found;
    }

    /**
     * One request, verified end to end.
     *
     * @param list<string> $names
     * @return array<string, list<mixed>>
     */
    private function query(Ecosystem $ecosystem, array $names): array
    {
        $nonce = rtrim(strtr(base64_encode(random_bytes(24)), '+/', '-_'), '=');
        $started = microtime(true);

        try {
            $response = $this->http->postJsonRaw('Valtry', $this->url, [
                'nonce' => $nonce,
                'packages' => array_map(fn (string $name): array => ['ecosystem' => $ecosystem->value, 'name' => $name], $names),
            ]);
        } catch (SourceUnavailable $e) {
            throw $this->failed($e->getMessage());
        }

        if (microtime(true) - $started > $this->deadline + 0.5) {
            throw $this->failed('Valtry couldn\'t be reached: it took longer than '.$this->deadline.' seconds.');
        }

        if ($response['status'] !== 200) {
            throw $this->failed('Valtry couldn\'t be reached: it answered HTTP '.$response['status'].'.');
        }

        if (! $this->verified($response['headers']['x-valtry-signature'] ?? '', $response['body'])) {
            throw $this->failed('Valtry\'s answer was refused: its signature didn\'t verify against a pinned key.');
        }

        try {
            $data = json_decode($response['body'], true, 64, JSON_THROW_ON_ERROR);
        } catch (Throwable) {
            throw $this->failed('Valtry\'s answer was refused: it wasn\'t JSON.');
        }

        if (! is_array($data) || ($data['v'] ?? null) !== 1 || ($data['nonce'] ?? null) !== $nonce || ! is_array($data['advisories'] ?? null)) {
            throw $this->failed('Valtry\'s answer was refused: it isn\'t an answer to this request.');
        }

        $stale = is_array($data['stale_ecosystems'] ?? null) ? $data['stale_ecosystems'] : (($data['stale'] ?? false) === true ? [$ecosystem->value] : []);
        if (in_array($ecosystem->value, $stale, true)) {
            throw new SourceUnavailable('Valtry', 'Valtry wasn\'t used: its '.$ecosystem->label().' data is out of date.');
        }

        $out = [];
        foreach ($names as $name) {
            $items = $data['advisories'][$ecosystem->value.':'.$name] ?? null;

            if (! is_array($items)) {
                throw $this->failed('Valtry\'s answer was refused: it left out packages that were asked about.');
            }

            $out[$name] = array_values($items);
        }

        return $out;
    }

    private function verified(string $header, string $body): bool
    {
        $signature = null;
        $kid = null;

        foreach (preg_split('/\s*[;,]\s*/', trim($header)) ?: [] as $part) {
            [$key, $value] = array_pad(explode('=', $part, 2), 2, '');

            if ($key === 'ed25519') {
                $signature = base64_decode($value, true);
            } elseif ($key === 'kid') {
                $kid = $value;
            }
        }

        if (! is_string($signature) || strlen($signature) !== 64 || $kid === null || ! isset($this->keys[$kid])) {
            return false;
        }

        try {
            return sodium_crypto_sign_verify_detached($signature, $body, $this->keys[$kid]);
        } catch (Throwable) {
            return false;
        }
    }

    private function failed(string $message): SourceUnavailable
    {
        $this->down = true;
        $this->cache->put(self::DOWN, ['since' => time()], self::BACKOFF);

        return new SourceUnavailable('Valtry', $message);
    }

    private static function usable(mixed $item): bool
    {
        return is_array($item) && is_string($item['id'] ?? null) && $item['id'] !== '' && is_string($item['affected'] ?? null) && $item['affected'] !== '';
    }

    /**
     * One advisory from Valtry, in the same shape the public sources give,
     * so a finding is the same whichever path found it (same key, title,
     * link and dates).
     *
     * @param array<mixed> $item
     */
    public static function advisory(Ecosystem $ecosystem, string $package, array $item): ?Advisory
    {
        if (! self::usable($item)) {
            return null;
        }

        $string = fn (string $key): ?string => is_string($item[$key] ?? null) && trim($item[$key]) !== '' ? trim($item[$key]) : null;
        $kev = ($item['exploited'] ?? false) === true && is_array($item['kev'] ?? null)
            ? KevEntry::fromArray(['cve' => $item['kev']['cve'] ?? $string('cve')] + $item['kev'] + ['name' => $string('cve')])
            : null;
        $published = $string('published_at');

        if ($ecosystem === Ecosystem::Composer) {
            // Packagist's own record shape, through the same reader as the public path.
            $base = PackagistAdvisorySource::advisory($package, [
                'advisoryId' => $item['id'],
                'packageName' => $package,
                'title' => $string('title'),
                'link' => $string('link'),
                'cve' => $string('cve'),
                'severity' => $string('severity'),
                'affectedVersions' => $item['affected'],
                'reportedAt' => self::date($published, 'Y-m-d H:i:s'),
            ]);

            return $base === null ? null : new Advisory(
                id: $base->id,
                ecosystem: $base->ecosystem,
                package: $base->package,
                title: $base->title,
                link: $base->link,
                cve: $base->cve,
                severity: $base->severity,
                affectedVersions: $base->affectedVersions,
                reportedAt: $base->reportedAt,
                kev: $kev,
                kevKnown: true,
            );
        }

        $cve = $string('cve');

        return new Advisory(
            id: (string) $item['id'],
            ecosystem: $ecosystem,
            package: $package,
            title: $string('title') ?? (string) $item['id'],
            link: $string('link'),
            cve: $cve !== null ? strtoupper($cve) : null,
            severity: Severity::parse($string('severity')),
            // Matching uses the constraint; the advisory keeps OSV's shape (no range string), as the public path does.
            affectedVersions: null,
            reportedAt: self::date($published, 'Y-m-d\TH:i:s\Z'),
            kev: $kev,
            kevKnown: true,
        );
    }

    private static function date(?string $value, string $format): ?string
    {
        if ($value === null) {
            return null;
        }

        try {
            return (new DateTimeImmutable($value, new DateTimeZone('UTC')))->setTimezone(new DateTimeZone('UTC'))->format($format);
        } catch (Throwable) {
            return $value;
        }
    }
}
