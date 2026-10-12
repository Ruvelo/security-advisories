<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

/**
 * Something worth telling a human that is not a finding and not a failure:
 * "an advisory names this package but its affected versions couldn't be read,
 * check by hand". Notes never make a report incomplete or block resolving.
 */
final readonly class Note
{
    public function __construct(
        public string $message,
        public ?Ecosystem $ecosystem = null,
        public ?string $package = null,
        public ?string $link = null,
    ) {
    }

    /**
     * @return array{message: string, ecosystem: string|null, package: string|null, link: string|null}
     */
    public function toArray(): array
    {
        return [
            'message' => $this->message,
            'ecosystem' => $this->ecosystem?->value,
            'package' => $this->package,
            'link' => $this->link,
        ];
    }

    /**
     * @param array<mixed> $data What toArray() gave
     */
    public static function fromArray(array $data): ?self
    {
        if (! is_string($data['message'] ?? null) || $data['message'] === '') {
            return null;
        }

        return new self(
            $data['message'],
            is_string($data['ecosystem'] ?? null) ? Ecosystem::tryFrom($data['ecosystem']) : null,
            is_string($data['package'] ?? null) ? $data['package'] : null,
            is_string($data['link'] ?? null) ? $data['link'] : null,
        );
    }
}
