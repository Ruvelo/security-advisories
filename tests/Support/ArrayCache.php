<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Support;

use DateInterval;
use Psr\SimpleCache\CacheInterface;

/**
 * A PSR-16 cache in memory that remembers the lifetimes it was given.
 */
final class ArrayCache implements CacheInterface
{
    /** @var array<string, mixed> */
    public array $items = [];

    /** @var array<string, int|null> */
    public array $ttls = [];

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->items[$key] ?? $default;
    }

    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $this->items[$key] = $value;
        $this->ttls[$key] = is_int($ttl) ? $ttl : null;

        return true;
    }

    public function delete(string $key): bool
    {
        unset($this->items[$key]);

        return true;
    }

    public function clear(): bool
    {
        $this->items = [];

        return true;
    }

    public function getMultiple(iterable $keys, mixed $default = null): iterable
    {
        $found = [];
        foreach ($keys as $key) {
            $found[$key] = $this->get($key, $default);
        }

        return $found;
    }

    /**
     * @param iterable<array-key, mixed> $values
     */
    public function setMultiple(iterable $values, DateInterval|int|null $ttl = null): bool
    {
        foreach ($values as $key => $value) {
            $this->set((string) $key, $value, $ttl);
        }

        return true;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        foreach ($keys as $key) {
            $this->delete($key);
        }

        return true;
    }

    public function has(string $key): bool
    {
        return isset($this->items[$key]);
    }
}
