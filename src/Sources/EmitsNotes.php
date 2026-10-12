<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Sources;

use Ruvelo\SecurityAdvisories\Note;

/**
 * An advisory source that can say more than findings. Optional: a source that
 * doesn't implement it works as before. The Scanner calls notes() once after
 * each find() and copies the result into Report::$notes.
 */
interface EmitsNotes
{
    /**
     * The notes from the last find(), replaced on every call to find().
     *
     * @return list<Note>
     */
    public function notes(): array;
}
