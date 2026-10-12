<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\Ecosystem;

/**
 * An advisory source that can say which path answered for an ecosystem
 * (FallbackAdvisorySource: "valtry" or "public"). The Scanner copies it into
 * Report::$sources.
 */
interface ReportsOrigin
{
    /**
     * The path that answered the last find() for this ecosystem, or null if none did.
     */
    public function origin(Ecosystem $ecosystem): ?string;
}
