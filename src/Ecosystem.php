<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * Where a package comes from, and so which advisory source covers it.
 *
 * Extension is for what a platform installs outside Composer and npm (a Joomla
 * extension, a PrestaShop module). Nothing here has advisories for those: the
 * adapter supplies its own AdvisorySource.
 */
enum Ecosystem: string
{
    case Composer = 'composer';
    case Npm = 'npm';
    case Extension = 'extension';

    public function label(): string
    {
        return match ($this) {
            self::Composer => 'Composer',
            self::Npm => 'npm',
            self::Extension => 'extension',
        };
    }
}
