<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories;

use DateTimeImmutable;
use DateTimeZone;

/**
 * An entry in CISA's Known Exploited Vulnerabilities catalogue: proof that
 * attackers are using this flaw in the wild.
 */
final readonly class KevEntry
{
    public function __construct(
        public string $cve,
        public string $name,
        public DateTimeImmutable $dateAdded,
        public ?DateTimeImmutable $dueDate = null,
        public bool $ransomware = false,
    ) {
    }

    /**
     * @param array<mixed> $data An item of the catalogue's "vulnerabilities" list
     */
    public static function fromCatalogue(array $data): ?self
    {
        $cve = $data['cveID'] ?? null;
        $added = $data['dateAdded'] ?? null;

        if (! is_string($cve) || ! is_string($added) || ($dateAdded = self::date($added)) === null) {
            return null;
        }

        $name = $data['vulnerabilityName'] ?? null;
        $due = $data['dueDate'] ?? null;
        $ransomware = $data['knownRansomwareCampaignUse'] ?? null;

        return new self(
            cve: strtoupper(trim($cve)),
            name: is_string($name) && trim($name) !== '' ? trim($name) : $cve,
            dateAdded: $dateAdded,
            dueDate: is_string($due) ? self::date($due) : null,
            ransomware: is_string($ransomware) && strtolower($ransomware) === 'known',
        );
    }

    /**
     * @param array<mixed> $data What toArray() gave
     */
    public static function fromArray(array $data): ?self
    {
        return self::fromCatalogue([
            'cveID' => $data['cve'] ?? null,
            'vulnerabilityName' => $data['name'] ?? null,
            'dateAdded' => $data['date_added'] ?? null,
            'dueDate' => $data['due_date'] ?? null,
            'knownRansomwareCampaignUse' => ($data['ransomware'] ?? false) === true ? 'Known' : 'Unknown',
        ]);
    }

    /**
     * @return array{cve: string, name: string, date_added: string, due_date: string|null, ransomware: bool}
     */
    public function toArray(): array
    {
        return [
            'cve' => $this->cve,
            'name' => $this->name,
            'date_added' => $this->dateAdded->format('Y-m-d'),
            'due_date' => $this->dueDate?->format('Y-m-d'),
            'ransomware' => $this->ransomware,
        ];
    }

    private static function date(string $value): ?DateTimeImmutable
    {
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $value) !== 1) {
            return null;
        }

        $date = DateTimeImmutable::createFromFormat('!Y-m-d', $value, new DateTimeZone('UTC'));

        return $date === false ? null : $date;
    }
}
