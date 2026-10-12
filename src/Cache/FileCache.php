<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Cache;

use Closure;
use DateInterval;
use DateTimeImmutable;
use Psr\SimpleCache\CacheInterface;

/**
 * A simple PSR-16 cache in a directory, for platforms without one.
 *
 * One file per key, named by a hash of the key, so any key is a safe file
 * name. Writes go to a temporary file in the same directory and are renamed
 * into place, so a reader sees the old entry or the new one, never half of one.
 * Values are stored with serialize() and read back without instantiating
 * classes, so keep to scalars and arrays (all this library caches).
 *
 * The directory is created (owner only) on first write. It is meant for this
 * library's own cache directory: clear() removes every cache file in it.
 */
final class FileCache implements CacheInterface
{
    private const SUFFIX = '.cache';

    /** @var Closure(): int */
    private readonly Closure $clock;

    /**
     * @param (callable(): int)|null $clock Current time as a Unix timestamp; for tests
     */
    public function __construct(private readonly string $directory, ?callable $clock = null)
    {
        $this->clock = $clock === null ? time(...) : $clock(...);
    }

    public function get(string $key, mixed $default = null): mixed
    {
        $entry = $this->read($key);

        return $entry === null ? $default : $entry[1];
    }

    public function set(string $key, mixed $value, DateInterval|int|null $ttl = null): bool
    {
        $path = $this->path($key);
        $expires = $this->expiry($ttl);

        if ($expires !== null && $expires <= ($this->clock)()) {
            return $this->delete($key);
        }

        if (! is_dir($this->directory) && ! @mkdir($this->directory, 0700, true) && ! is_dir($this->directory)) {
            return false;
        }

        $payload = serialize([$expires, $value]);
        $temporary = @tempnam($this->directory, '.tmp');

        if ($temporary === false) {
            return false;
        }

        if (@file_put_contents($temporary, $payload, LOCK_EX) !== strlen($payload) || ! @rename($temporary, $path)) {
            @unlink($temporary);

            return false;
        }

        return true;
    }

    public function delete(string $key): bool
    {
        $path = $this->path($key);

        return ! is_file($path) || @unlink($path) || ! is_file($path);
    }

    public function clear(): bool
    {
        $ok = true;

        foreach (glob(rtrim($this->directory, '/\\').'/*'.self::SUFFIX) ?: [] as $file) {
            $ok = (@unlink($file) || ! is_file($file)) && $ok;
        }

        return $ok;
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
        $ok = true;
        foreach ($values as $key => $value) {
            $ok = $this->set((string) $key, $value, $ttl) && $ok;
        }

        return $ok;
    }

    public function deleteMultiple(iterable $keys): bool
    {
        $ok = true;
        foreach ($keys as $key) {
            $ok = $this->delete($key) && $ok;
        }

        return $ok;
    }

    public function has(string $key): bool
    {
        return $this->read($key) !== null;
    }

    /**
     * @return array{int|null, mixed}|null The expiry and the value, or null if missing, expired or unreadable
     */
    private function read(string $key): ?array
    {
        $path = $this->path($key);
        $raw = is_file($path) ? @file_get_contents($path) : false;

        if ($raw === false) {
            return null;
        }

        $entry = @unserialize($raw, ['allowed_classes' => false]);

        if (! is_array($entry) || count($entry) !== 2 || ! array_key_exists(0, $entry) || ! array_key_exists(1, $entry) || ! (is_int($entry[0]) || $entry[0] === null)) {
            @unlink($path);

            return null;
        }

        if ($entry[0] !== null && $entry[0] <= ($this->clock)()) {
            @unlink($path);

            return null;
        }

        return [$entry[0], $entry[1]];
    }

    private function path(string $key): string
    {
        if ($key === '') {
            throw new InvalidKey('A cache key can\'t be empty.');
        }

        return rtrim($this->directory, '/\\').'/'.hash('sha256', $key).self::SUFFIX;
    }

    private function expiry(DateInterval|int|null $ttl): ?int
    {
        $now = ($this->clock)();

        if ($ttl instanceof DateInterval) {
            return (new DateTimeImmutable('@'.$now))->add($ttl)->getTimestamp();
        }

        return $ttl === null ? null : $now + $ttl;
    }
}
