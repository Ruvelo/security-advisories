<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\InvalidThreshold;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Threshold;

class ModelTest extends TestCase
{
    public static function finding(string $package = 'a/a', Severity $severity = Severity::High, ?KevEntry $kev = null, string $id = 'ADV-1', Ecosystem $ecosystem = Ecosystem::Composer): Finding
    {
        return new Finding($ecosystem, $package, '1.0.0', $id, 'Title', $severity, exploited: $kev);
    }

    public static function kev(string $added = '2026-03-20', bool $ransomware = false): KevEntry
    {
        return new KevEntry('CVE-2026-0001', 'Name', new DateTimeImmutable($added), new DateTimeImmutable('2026-04-03'), $ransomware);
    }

    public function testSeverityParsesTheSpellingsSourcesUse(): void
    {
        $this->assertSame(Severity::Medium, Severity::parse('MODERATE'));
        $this->assertSame(Severity::Critical, Severity::parse(' Critical '));
        $this->assertSame(Severity::NotRated, Severity::parse(null));
        $this->assertSame(Severity::NotRated, Severity::parse('banana'));
        $this->assertSame('Not rated', Severity::NotRated->label());
        $this->assertTrue(Severity::NotRated->atLeast(Severity::Low));
        $this->assertFalse(Severity::NotRated->atLeast(Severity::Medium));
    }

    public function testThresholds(): void
    {
        $exploited = self::finding(severity: Severity::Low, kev: self::kev());
        $critical = self::finding(severity: Severity::Critical);
        $notRated = self::finding(severity: Severity::NotRated);

        $this->assertTrue(Threshold::Exploited->isMetBy($exploited));
        $this->assertFalse(Threshold::Exploited->isMetBy($critical));
        $this->assertTrue(Threshold::Critical->isMetBy($exploited), 'Exploited always counts');
        $this->assertTrue(Threshold::Critical->isMetBy($critical));
        $this->assertFalse(Threshold::High->isMetBy($notRated));
        $this->assertTrue(Threshold::Any->isMetBy($notRated));
        $this->assertSame(Threshold::High, Threshold::parse(' HIGH '));

        $this->expectException(InvalidThreshold::class);
        Threshold::parse('severe');
    }

    public function testFindingsSortExploitedFirstThenBySeverity(): void
    {
        $report = new Report([
            self::finding('b/low', Severity::Low),
            self::finding('c/high', Severity::High),
            self::finding('d/exploited-old', Severity::Low, self::kev('2024-01-01')),
            self::finding('e/critical', Severity::Critical),
            self::finding('f/exploited-new', Severity::Low, self::kev('2026-03-20')),
            self::finding('g/unrated', Severity::NotRated),
            self::finding('a/high', Severity::High),
        ]);

        $this->assertSame(
            ['f/exploited-new', 'd/exploited-old', 'e/critical', 'a/high', 'c/high', 'g/unrated', 'b/low'],
            array_map(fn (Finding $f): string => $f->package, $report->findings),
        );
        $this->assertSame('f/exploited-new', $report->worst()?->package);
        $this->assertSame(['exploited' => 2, 'critical' => 1, 'high' => 2, 'low' => 1, 'not_rated' => 1], $report->counts());
        $this->assertCount(2, $report->exploited());
    }

    public function testFailsOn(): void
    {
        $report = new Report([self::finding(severity: Severity::High)]);

        $this->assertTrue($report->failsOn(Threshold::High));
        $this->assertTrue($report->failsOn(Threshold::Any));
        $this->assertFalse($report->failsOn(Threshold::Critical));
        $this->assertFalse($report->failsOn(Threshold::Exploited));
        $this->assertFalse((new Report([]))->failsOn(Threshold::Any));
        $this->assertNull((new Report([]))->worst());
    }

    public function testCleanIsNotTheSameAsComplete(): void
    {
        $incomplete = new Report([], problems: ['Packagist couldn\'t be reached.']);

        $this->assertTrue($incomplete->isClean());
        $this->assertFalse($incomplete->isComplete());
        $this->assertTrue((new Report([]))->isComplete());
    }

    public function testToArrayIsJsonReady(): void
    {
        $report = new Report(
            [self::finding('a/a', Severity::Critical, self::kev('2026-03-20', true))],
            ['composer' => 3],
            [Ecosystem::Composer],
            [],
            true,
            new DateTimeImmutable('2026-10-12T07:00:00+00:00'),
        );

        $data = json_decode((string) json_encode($report), true);

        $this->assertIsArray($data);
        $this->assertSame('2026-10-12T07:00:00+00:00', $data['checked_at']);
        $this->assertFalse($data['clean']);
        $this->assertTrue($data['complete']);
        $this->assertSame(['composer' => 3], $data['packages']);
        $this->assertSame(['composer'], $data['checked']);
        $this->assertSame(['exploited' => 1], $data['counts']);
        $this->assertSame('composer:a/a:ADV-1', $data['findings'][0]['key']);
        $this->assertSame('1.0.0', $data['findings'][0]['installed']);
        $this->assertSame('critical', $data['findings'][0]['severity']);
        $this->assertTrue($data['findings'][0]['exploited']);
        $this->assertSame(
            ['cve' => 'CVE-2026-0001', 'name' => 'Name', 'date_added' => '2026-03-20', 'due_date' => '2026-04-03', 'ransomware' => true],
            $data['findings'][0]['kev'],
        );
    }

    public function testKevEntryRoundTripsAndRejectsGarbage(): void
    {
        $entry = KevEntry::fromCatalogue([
            'cveID' => 'cve-2025-54068', 'vulnerabilityName' => ' Livewire RCE ', 'dateAdded' => '2026-03-20',
            'dueDate' => '2026-04-03', 'knownRansomwareCampaignUse' => 'Known',
        ]);

        $this->assertNotNull($entry);
        $this->assertSame('CVE-2025-54068', $entry->cve);
        $this->assertSame('Livewire RCE', $entry->name);
        $this->assertTrue($entry->ransomware);
        $this->assertEquals($entry, KevEntry::fromArray($entry->toArray()));
        $this->assertNull(KevEntry::fromCatalogue(['cveID' => 'CVE-1', 'dateAdded' => 'yesterday']));
        $this->assertNull(KevEntry::fromCatalogue(['dateAdded' => '2026-03-20']));
    }

    public function testAFindingSurvivesARoundTripThroughItsArray(): void
    {
        $finding = new Finding(Ecosystem::Npm, '@scope/pkg', '1.2.0', 'GHSA-1', 'Title', Severity::Critical, 'https://x', 'CVE-2026-1', '1.2.1', '<1.2.1', '2026-01-01', self::kev(), true);

        $this->assertEquals($finding, Finding::fromArray($finding->toArray()));
        $this->assertNull(Finding::fromArray(['package' => 'a/a']));
        $this->assertNull(Finding::fromArray(['ecosystem' => 'pypi', 'package' => 'a', 'advisory_id' => 'X']));
    }

    public function testAReportSaysWhichPathAnswered(): void
    {
        $this->assertSame('public', (new Report([]))->source);
        $this->assertSame('valtry', (new Report([], sources: ['composer' => 'valtry', 'npm' => 'valtry']))->source);
        $this->assertSame('mixed', (new Report([], sources: ['composer' => 'valtry', 'npm' => 'public']))->source);
        $this->assertSame(['composer' => 'valtry'], (new Report([], sources: ['composer' => 'valtry']))->toArray()['sources']);
    }
}
