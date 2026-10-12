<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Note;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Tests\Support\StubSource;
use Ruvelo\SecurityAdvisories\UncheckedPackage;

class AdapterSupportTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../fixtures';

    private function match(InstalledPackage $package, string $id = 'PLUGIN-1', ?string $constraint = '<2.0.0'): AdvisoryMatch
    {
        return new AdvisoryMatch($package, new Advisory($id, $package->ecosystem, $package->name, 'A flaw', 'https://example.test/'.$id, affectedVersions: $constraint, severity: Severity::High), '2.0.0');
    }

    public function testPackagesWithoutASourceAreUncheckedAndDoNotBreakCompleteness(): void
    {
        $zip = new InstalledPackage(Ecosystem::Extension, 'acme/zipped', '1.0.0', metadata: ['source' => 'zip']);
        $scanner = new Scanner([new ExtensionList([$zip, ['name' => 'acme/other', 'version' => '2.0.0']])], []);

        $report = $scanner->scan();

        $this->assertTrue($report->isComplete());
        $this->assertTrue($report->isClean());
        $this->assertSame([], $report->problems);
        $this->assertCount(2, $report->unchecked);
        $this->assertInstanceOf(UncheckedPackage::class, $report->unchecked[0]);
        $this->assertSame($zip, $report->unchecked[0]->package);
        $this->assertNotSame('', $report->unchecked[0]->reason);
        $this->assertSame(2, $report->packageCount(Ecosystem::Extension));
        $this->assertFalse($report->isCheckedFor(Ecosystem::Extension), 'unchecked packages never resolve findings');
    }

    public function testRealProblemsStillMakeTheReportIncomplete(): void
    {
        $failing = new StubSource([Ecosystem::Composer], fn (array $p): array => throw new SourceUnavailable('Stub', 'Stub is down.'));
        $scanner = new Scanner([new ExtensionList([['name' => 'a/b', 'version' => '1.0.0']], Ecosystem::Composer), new ExtensionList([['name' => 'x', 'version' => '1']])], [$failing]);

        $report = $scanner->scan();

        $this->assertFalse($report->isComplete());
        $this->assertCount(1, $report->problems);
        $this->assertCount(1, $report->unchecked);
    }

    public function testASourceCoveringOnlyPartOfTheInventoryChecksThatPart(): void
    {
        $source = new StubSource([Ecosystem::Extension], fn (array $packages): array => array_map(fn (InstalledPackage $p): AdvisoryMatch => $this->match($p), $packages));
        $scanner = new Scanner([new ExtensionList([['name' => 'a', 'version' => '1.0.0']]), new ExtensionList([['name' => 'b', 'version' => '1.0.0']], Ecosystem::Npm)], [$source]);

        $report = $scanner->scan();

        $this->assertCount(1, $report->findings);
        $this->assertCount(1, $report->unchecked);
        $this->assertSame('b', $report->unchecked[0]->package->name);
        $this->assertTrue($report->isComplete());
    }

    public function testNotesComeFromSourcesAndDoNotBlockAnything(): void
    {
        $note = new Note('Affected versions unreadable, check by hand.', Ecosystem::Extension, 'acme/plugin', 'https://example.test/advisory');
        $source = new StubSource([Ecosystem::Extension], fn (array $p): array => [$this->match($p[0])], [$note, $note]);
        $scanner = new Scanner([new ExtensionList([['name' => 'acme/plugin', 'version' => '1.0.0']])], [$source]);

        $report = $scanner->scan();

        $this->assertSame([$note], $report->notes, 'the same note twice is one note');
        $this->assertTrue($report->hasNotes());
        $this->assertTrue($report->isComplete());
        $this->assertTrue($report->isCheckedFor(Ecosystem::Extension));

        $known = [];
        $this->assertCount(1, (new Reconciler())->reconcile($known, $report)->new);
        $this->assertSame(['acme/plugin'], array_map(fn (Note $n): ?string => $n->package, $report->notes));
    }

    public function testSourcesWithoutNotesNeedNoChange(): void
    {
        $plain = new class () implements \Ruvelo\SecurityAdvisories\Sources\AdvisorySource {
            public function supports(Ecosystem $ecosystem): bool
            {
                return true;
            }

            public function find(array $packages, bool $fresh = false): array
            {
                return [];
            }
        };

        $report = (new Scanner([new ExtensionList([['name' => 'a', 'version' => '1.0.0']])], [$plain]))->scan();

        $this->assertSame([], $report->notes);
        $this->assertFalse($report->hasNotes());
    }

    public function testTheFallbackSourcePassesNotesThrough(): void
    {
        $note = new Note('From the fallback.');
        $primary = new StubSource([Ecosystem::Composer], fn (array $p): array => throw new SourceUnavailable('Stub', 'down'), [new Note('Never seen.')]);
        $fallback = new StubSource([Ecosystem::Composer], fn (array $p): array => [], [$note]);
        $chain = new FallbackAdvisorySource($primary, [$fallback]);

        $chain->find([new InstalledPackage(Ecosystem::Composer, 'a/b', '1.0.0')]);

        $this->assertSame([$note], $chain->notes());
    }

    public function testEcosystemsCanBeChosen(): void
    {
        $client = MockClient::feeds();
        $factory = new Psr17Factory();
        $http = new JsonClient($client, $factory, $factory);

        $report = Scanner::forProject(self::FIXTURES, $http, ecosystems: [Ecosystem::Composer], source: 'public')->scan();

        $this->assertSame([Ecosystem::Composer], $report->checked);
        $this->assertSame([Ecosystem::Composer->value], array_keys($report->packages));
        $this->assertSame([], $client->sentTo('osv.dev'), 'npm was not asked about');
        $this->assertNotSame([], $client->sentTo('packagist.org'));
        $this->assertSame([], $client->stray);
        $this->assertSame([], $report->unchecked);
    }

    public function testNpmOnlyAndTheDefaultStillCoverBoth(): void
    {
        $client = MockClient::feeds();
        $factory = new Psr17Factory();
        $http = new JsonClient($client, $factory, $factory);

        $npm = Scanner::forProject(self::FIXTURES, $http, ecosystems: [Ecosystem::Npm], source: 'public')->scan();
        $this->assertSame([Ecosystem::Npm], $npm->checked);
        $this->assertSame([], $client->sentTo('packagist.org'));

        $both = Scanner::forProject(self::FIXTURES, $http, source: 'public')->scan();
        $this->assertEqualsCanonicalizing([Ecosystem::Composer, Ecosystem::Npm], $both->checked);
    }

    public function testExtraSourcesAndPackageSourcesJoinTheBuiltInOnes(): void
    {
        $client = MockClient::feeds();
        $factory = new Psr17Factory();
        $http = new JsonClient($client, $factory, $factory);
        $plugin = new InstalledPackage(Ecosystem::Extension, 'acme/plugin', '1.0.0', metadata: ['active' => false]);
        $own = new StubSource([Ecosystem::Extension], fn (array $p): array => [$this->match($p[0])]);

        $report = Scanner::forProject(
            self::FIXTURES,
            $http,
            ecosystems: [Ecosystem::Composer],
            source: 'public',
            extraSources: [$own],
            extraPackageSources: [new ExtensionList([$plugin])],
        )->scan();

        $this->assertEqualsCanonicalizing([Ecosystem::Composer, Ecosystem::Extension], $report->checked);
        $ours = array_values(array_filter($report->findings, fn (Finding $f): bool => $f->ecosystem === Ecosystem::Extension));
        $this->assertCount(1, $ours);
        $this->assertSame(['active' => false], $ours[0]->metadata);
        $this->assertNotSame([], array_filter($report->findings, fn (Finding $f): bool => $f->ecosystem === Ecosystem::Composer));
    }

    public function testNoBuiltInEcosystemsMeansOnlyTheExtras(): void
    {
        $own = new StubSource([Ecosystem::Extension], fn (array $p): array => []);
        $scanner = Scanner::forProject(self::FIXTURES, ecosystems: [], extraSources: [$own], extraPackageSources: [new ExtensionList([['name' => 'a', 'version' => '1']])], exploits: new class () implements \Ruvelo\SecurityAdvisories\Sources\ExploitCatalogue {
            public function lookup(array $cves, bool $fresh = false): array
            {
                return [];
            }
        });

        $report = $scanner->scan();

        $this->assertSame([Ecosystem::Extension], $report->checked);
        $this->assertSame(['extension' => 1], $report->packages);
    }

    public function testMetadataPassesFromPackageToFindingAndKeepsOnlyScalars(): void
    {
        $package = new InstalledPackage(Ecosystem::Extension, 'acme/plugin', '1.0.0', false, ['active' => false, 'source' => 'zip', 'build' => 7, 'nested' => ['x'], 3 => 'numeric key']);

        $this->assertSame(['active' => false, 'source' => 'zip', 'build' => 7], $package->metadata);

        $finding = Finding::from($this->match($package));
        $this->assertSame(['active' => false, 'source' => 'zip', 'build' => 7], $finding->metadata);
        $this->assertSame(['active' => false, 'source' => 'zip', 'build' => 7], $finding->toArray()['meta']);
    }

    public function testExtensionListTakesMetadataInArrays(): void
    {
        $list = new ExtensionList([['name' => 'a', 'version' => '1', 'metadata' => ['active' => false]]]);

        $this->assertSame(['active' => false], $list->packages()[0]->metadata);
        $this->assertSame([], (new InstalledPackage(Ecosystem::Npm, 'x', '1'))->metadata);
    }

    public function testAFindingSurvivesTheRoundTrip(): void
    {
        $package = new InstalledPackage(Ecosystem::Composer, 'acme/lib', '1.2.3', true, ['active' => true]);
        $advisory = new Advisory('GHSA-aaaa', Ecosystem::Composer, 'acme/lib', 'Boom', 'https://x.test/1', 'CVE-2026-0001', Severity::Critical, '<1.3.0', '1.3.0', '2026-01-01', aliases: ['GHSA-bbbb'], links: ['https://x.test/2']);
        $kev = new KevEntry('CVE-2026-0001', 'Boom', new \DateTimeImmutable('2026-02-01'), new \DateTimeImmutable('2026-02-22'), true);
        $finding = Finding::from(new AdvisoryMatch($package, $advisory, '1.3.0'), $kev);

        $stored = json_decode((string) json_encode($finding), true);
        $again = Finding::fromArray($stored);

        $this->assertSame(Finding::SHAPE, $stored['v']);
        $this->assertNotNull($again);
        $this->assertSame($finding->toArray(), $again->toArray());
        $this->assertSame(['GHSA-bbbb'], $again->aliases);
        $this->assertSame(['https://x.test/2'], $again->links);
        $this->assertSame(['active' => true], $again->metadata);
        $this->assertTrue($again->isExploited());
        $this->assertTrue($again->isDev);
    }

    public function testFromArrayReadsWhatOneZeroStored(): void
    {
        $old = ['ecosystem' => 'composer', 'package' => 'a/b', 'installed' => '1.0.0', 'advisory_id' => 'X-1', 'title' => 'T', 'severity' => 'high'];

        $finding = Finding::fromArray($old);

        $this->assertNotNull($finding);
        $this->assertSame([], $finding->aliases);
        $this->assertSame([], $finding->metadata);
        $this->assertNull(Finding::fromArray(['package' => 'a/b']));
    }

    public function testAReportSurvivesTheRoundTrip(): void
    {
        $zip = new InstalledPackage(Ecosystem::Extension, 'acme/zipped', '1.0.0', metadata: ['source' => 'zip']);
        $source = new StubSource([Ecosystem::Composer], fn (array $p): array => [$this->match($p[0])], [new Note('Check by hand.', Ecosystem::Composer, 'a/b', 'https://x.test')]);
        $scanner = new Scanner([new ExtensionList([['name' => 'a/b', 'version' => '1.0.0']], Ecosystem::Composer), new ExtensionList([$zip])], [$source]);
        $report = $scanner->scan();

        $stored = json_decode((string) json_encode($report), true);
        $again = Report::fromArray($stored);

        $this->assertSame($stored, json_decode((string) json_encode($again), true));
        $this->assertCount(1, $again->findings);
        $this->assertSame('zip', $again->unchecked[0]->package->metadata['source']);
        $this->assertSame('Check by hand.', $again->notes[0]->message);
        $this->assertSame([Ecosystem::Composer], $again->checked);
        $this->assertEquals($report->checkedAt?->getTimestamp(), $again->checkedAt?->getTimestamp());
        $this->assertTrue($again->isComplete());
    }

    public function testReportFromArrayToleratesGarbage(): void
    {
        $report = Report::fromArray(['findings' => [['nope' => 1], 'x'], 'checked' => ['composer', 'unknown'], 'packages' => ['composer' => 'many'], 'checked_at' => 'not a date', 'notes' => [[]]]);

        $this->assertSame([], $report->findings);
        $this->assertSame([Ecosystem::Composer], $report->checked);
        $this->assertSame([], $report->packages);
        $this->assertNull($report->checkedAt);
        $this->assertSame([], $report->notes);
    }

    public function testStoredFindingsFeedTheReconciler(): void
    {
        $package = new InstalledPackage(Ecosystem::Composer, 'a/b', '1.0.0');
        $finding = Finding::from($this->match($package));
        $report = new Report([$finding], checked: [Ecosystem::Composer]);
        $reconciler = new Reconciler();

        $known = $reconciler->next([], $report);
        $lastSeen = $reconciler->lastSeen([], $report, $known);
        $stored = json_decode((string) json_encode(['known' => $known, 'last' => $lastSeen]), true);

        $later = new Report([], checked: [Ecosystem::Composer]);
        $changes = $reconciler->reconcile($stored['known'], $later, $stored['last']);

        $this->assertSame([$finding->key()], $changes->resolved);
        $this->assertSame($finding->toArray(), $changes->resolvedFinding($finding->key())?->toArray());
    }
}
