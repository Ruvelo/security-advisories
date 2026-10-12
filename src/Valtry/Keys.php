<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Valtry;

/**
 * The Ed25519 public keys Valtry signs its Advisory API answers with, pinned
 * in the library: an answer is only trusted when its signature verifies
 * against one of these. A key fetched from Valtry itself would prove nothing,
 * so they ship here, by key id ("kid").
 *
 * Until the owner pins the real key, the entries are placeholders and the
 * Valtry source is fail-closed: it sends nothing and the scan uses the public
 * feeds. A tagged release with a placeholder left fails CI.
 *
 * To pin a key: run `php artisan advisories:keygen` on Valtry, paste the
 * printed "'kid' => 'base64'," line below, release, and only then switch
 * Valtry to that key. Rotation: add the new kid beside the old one, release,
 * switch Valtry, and drop the old kid a release later.
 */
final class Keys
{
    public const PLACEHOLDER = 'PLACEHOLDER-run-advisories:keygen-on-Valtry-and-pin-the-public-key-here';

    /** kid => base64 Ed25519 public key (32 bytes). */
    public const PINNED = [
        'valtry-1' => self::PLACEHOLDER,
    ];

    /**
     * The usable keys: placeholders and malformed entries are left out.
     *
     * @param array<mixed> $keys kid => base64 public key
     * @return array<string, non-empty-string> kid => raw 32-byte public key
     */
    public static function decode(array $keys = self::PINNED): array
    {
        $out = [];

        foreach ($keys as $kid => $key) {
            if (! is_string($kid) || ! is_string($key) || $key === self::PLACEHOLDER) {
                continue;
            }

            $raw = base64_decode($key, true);

            if ($raw !== false && $raw !== '' && strlen($raw) === 32) {
                $out[$kid] = $raw;
            }
        }

        return $out;
    }

    /**
     * True while any entry (the pinned ones by default) is still a placeholder.
     *
     * @param array<mixed> $keys
     */
    public static function hasPlaceholders(array $keys = self::PINNED): bool
    {
        return in_array(self::PLACEHOLDER, $keys, true);
    }
}
