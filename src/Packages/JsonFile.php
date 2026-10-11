<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Packages;

use JsonException;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;

/**
 * @internal
 */
final class JsonFile
{
    /**
     * @return array<mixed>|null Null when the file doesn't exist
     *
     * @throws PackagesUnreadable
     */
    public static function read(string $path): ?array
    {
        if (! is_file($path)) {
            return null;
        }

        $contents = @file_get_contents($path);

        if ($contents === false) {
            throw PackagesUnreadable::at($path, 'it isn\'t readable');
        }

        try {
            $data = json_decode($contents, true, 512, JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw PackagesUnreadable::at($path, 'it isn\'t valid JSON ('.$e->getMessage().')');
        }

        if (! is_array($data)) {
            throw PackagesUnreadable::at($path, 'it doesn\'t hold a JSON object');
        }

        return $data;
    }
}
