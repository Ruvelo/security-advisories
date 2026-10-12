<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Cache;

use InvalidArgumentException;
use Psr\SimpleCache\InvalidArgumentException as SimpleCacheInvalidArgument;

final class InvalidKey extends InvalidArgumentException implements SimpleCacheInvalidArgument
{
}
