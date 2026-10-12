<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Cache;

use Closure;
use Psr\SimpleCache\CacheInterface;
use Throwable;

/**
 * An optional PSR-16 cache for feed responses. Without one every call fetches.
 * A cache that fails is skipped: it never turns into a failed scan.
 */
final class ResponseCache
{
    private const PREFIX = 'ruvelo.security-advisories.';

    public function __construct(
        private readonly ?CacheInterface $cache = null,
        public readonly Ttls $ttls = new Ttls(),
    ) {
    }

    /**
     * @param Closure(): array<mixed> $fetch
     * @return array<mixed>
     */
    public function remember(string $key, int $ttl, bool $fresh, Closure $fetch): array
    {
        $cached = $fresh ? null : $this->get($key, $ttl);

        if ($cached !== null) {
            return $cached;
        }

        $value = $fetch();

        if ($this->cache !== null && $ttl > 0) {
            try {
                $this->cache->set(self::PREFIX.$key, $value, $ttl);
            } catch (Throwable) {
                // Not worth failing a scan for.
            }
        }

        return $value;
    }

    /**
     * @param array<mixed> $value
     */
    public function put(string $key, array $value, int $ttl): void
    {
        if ($this->cache === null || $ttl <= 0) {
            return;
        }

        try {
            $this->cache->set(self::PREFIX.$key, $value, $ttl);
        } catch (Throwable) {
            // Not worth failing a scan for.
        }
    }

    /**
     * @return array<mixed>|null
     */
    public function get(string $key, int $ttl): ?array
    {
        if ($this->cache === null || $ttl <= 0) {
            return null;
        }

        try {
            $value = $this->cache->get(self::PREFIX.$key);
        } catch (Throwable) {
            return null;
        }

        return is_array($value) ? $value : null;
    }
}
