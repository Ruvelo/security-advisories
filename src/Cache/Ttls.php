<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Cache;

/**
 * How long responses are cached, in seconds. 0 turns a cache off.
 */
final readonly class Ttls
{
    public function __construct(
        public int $advisories = 3600,
        public int $kev = 21600,
        public int $osvDetails = 604800,
    ) {
    }
}
