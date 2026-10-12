<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\ExploitCatalogue;
use Ruvelo\SecurityAdvisories\Sources\MatchMerger;
use Ruvelo\SecurityAdvisories\Tests\Support\StubSource;

class DedupeTest extends TestCase
{
    private InstalledPackage $package;

    protected function setUp(): void
    {
        $this->package = new InstalledPackage(Ecosystem::Composer, 'acme/lib', '1.0.0');
    }

    /**
     * @param list<string> $aliases
     * @param list<string> $links
     */
    private function match(string $id, ?string $cve = null, ?string $constraint = null, ?string $fixedIn = null, array $aliases = [], ?string $link = null, array $links = []): AdvisoryMatch
    {
        return new AdvisoryMatch($this->package, new Advisory($id, Ecosystem::Composer, 'acme/lib', 'Title '.$id, $link, $cve, Severity::High, $constraint, $fixedIn, aliases: $aliases, links: $links), $fixedIn);
    }

    /**
     * @param list<AdvisoryMatch> $matches
     */
    private function scan(array $matches, ?ExploitCatalogue $exploits = null): \Ruvelo\SecurityAdvisories\Report
    {
        return (new Scanner(
            [new ExtensionList([$this->package], Ecosystem::Composer)],
            [new StubSource([Ecosystem::Composer], fn (): array => $matches)],
            $exploits,
        ))->scan();
    }

    public function testTheSameCveFromTwoSourcesIsOneFinding(): void
    {
        $report = $this->scan([$this->match('GHSA-1', 'CVE-2026-0001'), $this->match('PKSA-1', 'CVE-2026-0001')]);

        $this->assertCount(1, $report->findings);
    }

    public function testAnAliasOverlapIsOneFindingEvenWithoutAMatchingCve(): void
    {
        $report = $this->scan([$this->match('PKSA-1', null, aliases: ['GHSA-xxxx']), $this->match('GHSA-XXXX', null)]);

        $this->assertCount(1, $report->findings);
        $this->assertSame('PKSA-1', $report->findings[0]->advisoryId);
    }

    public function testAnIdThatIsAnotherAdvisorysCveOverlaps(): void
    {
        $report = $this->scan([$this->match('CVE-2026-0002'), $this->match('GHSA-2', 'cve-2026-0002')]);

        $this->assertCount(1, $report->findings);
    }

    public function testUnrelatedAdvisoriesOnTheSamePackageStaySeparate(): void
    {
        $report = $this->scan([$this->match('A-1', 'CVE-2026-0001'), $this->match('A-2', 'CVE-2026-0002')]);

        $this->assertCount(2, $report->findings);
    }

    public function testTheSameCveOnAnotherPackageStaysSeparate(): void
    {
        $other = new InstalledPackage(Ecosystem::Composer, 'acme/other', '1.0.0');
        $second = new AdvisoryMatch($other, new Advisory('A-1', Ecosystem::Composer, 'acme/other', 'T', cve: 'CVE-2026-0001'));

        $merged = MatchMerger::merge([$this->match('A-1', 'CVE-2026-0001'), $second]);

        $this->assertCount(2, $merged);
    }

    public function testTheSourceWithExactRangesWins(): void
    {
        $guess = $this->match('OSV-1', 'CVE-2026-0001', fixedIn: '1.5.0');
        $exact = $this->match('PKSA-1', 'CVE-2026-0001', constraint: '<1.5.0', fixedIn: '1.4.9');

        foreach ([[$guess, $exact], [$exact, $guess]] as $order) {
            $report = $this->scan($order);

            $this->assertCount(1, $report->findings);
            $this->assertSame('PKSA-1', $report->findings[0]->advisoryId);
            $this->assertSame('<1.5.0', $report->findings[0]->affectedVersions);
            $this->assertSame('1.4.9', $report->findings[0]->fixedIn);
        }
    }

    public function testAMatchThatNamesAFixBeatsOneThatDoesNot(): void
    {
        $report = $this->scan([$this->match('A-1', 'CVE-2026-0001'), $this->match('B-1', 'CVE-2026-0001', fixedIn: '2.0.0')]);

        $this->assertSame('B-1', $report->findings[0]->advisoryId);
        $this->assertSame('2.0.0', $report->findings[0]->fixedIn);
    }

    public function testTheLoserFillsInWhatTheWinnerLacks(): void
    {
        $winner = $this->match('PKSA-1', null, constraint: '<2.0.0', aliases: ['GHSA-1']);
        $loser = $this->match('GHSA-1', 'CVE-2026-0001', fixedIn: '2.0.0', link: 'https://github.test/GHSA-1');

        $finding = $this->scan([$loser, $winner])->findings[0];

        $this->assertSame('PKSA-1', $finding->advisoryId);
        $this->assertSame('CVE-2026-0001', $finding->cve);
        $this->assertSame('2.0.0', $finding->fixedIn);
        $this->assertSame('https://github.test/GHSA-1', $finding->link);
    }

    public function testAliasesAndLinksAreMerged(): void
    {
        $a = $this->match('PKSA-1', 'CVE-2026-0001', '<2.0.0', link: 'https://packagist.test/1', aliases: ['GHSA-aaaa'], links: ['https://extra.test/a']);
        $b = $this->match('GHSA-aaaa', 'CVE-2026-0001', link: 'https://github.test/aaaa', aliases: ['SA-CORE-1'], links: ['https://extra.test/a', 'https://extra.test/b']);

        $finding = $this->scan([$a, $b])->findings[0];

        $this->assertSame('https://packagist.test/1', $finding->link);
        $this->assertEqualsCanonicalizing(['GHSA-aaaa', 'CVE-2026-0001', 'SA-CORE-1'], $finding->aliases);
        $this->assertEqualsCanonicalizing(['https://extra.test/a', 'https://github.test/aaaa', 'https://extra.test/b'], $finding->links);
        $this->assertNotContains('PKSA-1', $finding->aliases, 'the finding\'s own id is not an alias');
    }

    public function testExploitedFromEitherSourceIsKept(): void
    {
        $kev = new KevEntry('CVE-2026-0001', 'Boom', new DateTimeImmutable('2026-02-01'), null, false);
        $withKev = new AdvisoryMatch($this->package, new Advisory('V-1', Ecosystem::Composer, 'acme/lib', 'T', cve: 'CVE-2026-0001', kev: $kev, kevKnown: true));
        $without = new AdvisoryMatch($this->package, new Advisory('PKSA-1', Ecosystem::Composer, 'acme/lib', 'T', cve: 'CVE-2026-0001', affectedVersions: '<2.0.0', kev: null, kevKnown: true));

        foreach ([[$withKev, $without], [$without, $withKev]] as $order) {
            $finding = $this->scan($order)->findings[0];

            $this->assertSame('PKSA-1', $finding->advisoryId, 'range preference decides the id');
            $this->assertTrue($finding->isExploited(), 'but the exploited flag survives');
        }
    }

    public function testTheCatalogueIsStillAskedAboutCvesFoundOnlyAsAliases(): void
    {
        $kev = new KevEntry('CVE-2026-0009', 'Boom', new DateTimeImmutable('2026-02-01'), null, false);
        $catalogue = new class ($kev) implements ExploitCatalogue {
            /** @var list<string> */
            public array $asked = [];

            public function __construct(private readonly KevEntry $kev)
            {
            }

            public function lookup(array $cves, bool $fresh = false): array
            {
                $this->asked = $cves;

                return ['CVE-2026-0009' => $this->kev];
            }
        };

        $report = $this->scan([$this->match('GHSA-9', null, aliases: ['CVE-2026-0009'])], $catalogue);

        $this->assertSame(['CVE-2026-0009'], $catalogue->asked);
        $this->assertTrue($report->findings[0]->isExploited());
    }

    public function testAChainOfOverlapsCollapsesToOne(): void
    {
        $merged = MatchMerger::merge([
            $this->match('A', null, aliases: ['B']),
            $this->match('C', null, aliases: ['D']),
            $this->match('B', null, aliases: ['D']),
        ]);

        $this->assertCount(1, $merged);
    }

    public function testTheHighestSeverityIsKeptWhenTheWinnerIsNotRated(): void
    {
        $winner = new AdvisoryMatch($this->package, new Advisory('PKSA-1', Ecosystem::Composer, 'acme/lib', 'T', cve: 'CVE-2026-0001', affectedVersions: '<2'));
        $other = new AdvisoryMatch($this->package, new Advisory('GHSA-1', Ecosystem::Composer, 'acme/lib', 'T', cve: 'CVE-2026-0001', severity: Severity::Critical));

        $this->assertSame(Severity::Critical, $this->scan([$winner, $other])->findings[0]->severity);
    }
}
