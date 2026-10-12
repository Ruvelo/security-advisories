<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Severity;

class ReconcilerTest extends TestCase
{
    /**
     * @param list<Finding> $findings
     * @param list<Ecosystem> $checked
     * @param list<string> $problems
     */
    private function report(array $findings, array $checked = [Ecosystem::Composer, Ecosystem::Npm], array $problems = []): Report
    {
        return new Report($findings, checked: $checked, problems: $problems);
    }

    private function key(string $package, string $id = 'ADV-1', Ecosystem $ecosystem = Ecosystem::Composer): string
    {
        return ModelTest::finding($package, id: $id, ecosystem: $ecosystem)->key();
    }

    public function testEverythingIsNewTheFirstTime(): void
    {
        $changes = (new Reconciler())->reconcile([], $this->report([
            ModelTest::finding('a/a'),
            ModelTest::finding('b/b', kev: ModelTest::kev()),
        ]));

        $this->assertSame(['b/b', 'a/a'], array_map(fn (Finding $f): string => $f->package, $changes->new));
        $this->assertSame(['b/b'], array_map(fn (Finding $f): string => $f->package, $changes->exploited), 'Arriving exploited counts');
        $this->assertSame([], $changes->resolved);
        $this->assertFalse($changes->isEmpty());
    }

    public function testNothingIsNewTheSecondTime(): void
    {
        $report = $this->report([ModelTest::finding('a/a'), ModelTest::finding('b/b', kev: ModelTest::kev())]);
        $known = (new Reconciler())->next([], $report);

        $this->assertSame([$this->key('b/b') => true, $this->key('a/a') => false], $known);
        $this->assertTrue((new Reconciler())->reconcile($known, $report)->isEmpty());
    }

    public function testAKnownFindingThatBecomesExploited(): void
    {
        $known = [$this->key('a/a') => false];
        $report = $this->report([ModelTest::finding('a/a', kev: ModelTest::kev())]);

        $changes = (new Reconciler())->reconcile($known, $report);

        $this->assertSame([], $changes->new);
        $this->assertSame(['a/a'], array_map(fn (Finding $f): string => $f->package, $changes->exploited));
        $this->assertSame([$this->key('a/a') => true], (new Reconciler())->next($known, $report));
    }

    public function testOnceExploitedAlwaysExploited(): void
    {
        $known = [$this->key('a/a') => true];
        // The catalogue was unreachable this time, so the finding no longer carries it.
        $report = $this->report([ModelTest::finding('a/a')]);

        $this->assertTrue((new Reconciler())->reconcile($known, $report)->isEmpty());
        $this->assertSame($known, (new Reconciler())->next($known, $report));
    }

    public function testWhatIsGoneIsResolved(): void
    {
        $known = [$this->key('a/a') => false, $this->key('b/b') => true];

        $changes = (new Reconciler())->reconcile($known, $this->report([ModelTest::finding('a/a')]));

        $this->assertSame([$this->key('b/b')], $changes->resolved);
        $this->assertSame([$this->key('a/a') => false], (new Reconciler())->next($known, $this->report([ModelTest::finding('a/a')])));
    }

    public function testAnIncompleteReportResolvesNothing(): void
    {
        $known = [$this->key('a/a') => false];
        $report = $this->report([], problems: ['Packagist couldn\'t be reached.']);

        $this->assertSame([], (new Reconciler())->reconcile($known, $report)->resolved);
        $this->assertSame($known, (new Reconciler())->next($known, $report));
    }

    public function testAnIncompleteReportStillReportsNews(): void
    {
        $report = $this->report([ModelTest::finding('a/a')], problems: ['CISA KEV couldn\'t be reached.']);

        $this->assertCount(1, (new Reconciler())->reconcile([], $report)->new);
    }

    public function testOnlyCheckedEcosystemsResolve(): void
    {
        $known = [$this->key('a/a') => false, $this->key('vite', 'GHSA-1', Ecosystem::Npm) => false, 'extension:com_x:X-1' => false];

        $changes = (new Reconciler())->reconcile($known, $this->report([], checked: [Ecosystem::Npm]));

        $this->assertSame([$this->key('vite', 'GHSA-1', Ecosystem::Npm)], $changes->resolved);
    }

    public function testAFixedFindingThatComesBackIsNewAgain(): void
    {
        $reconciler = new Reconciler();
        $report = $this->report([ModelTest::finding('a/a')]);

        $known = $reconciler->next([], $report);
        $known = $reconciler->next($known, $this->report([]));
        $this->assertSame([], $known);

        $this->assertCount(1, $reconciler->reconcile($known, $report)->new);
    }

    public function testSeverityDoesNotMatterToIdentity(): void
    {
        $known = [$this->key('a/a') => false];

        $this->assertTrue((new Reconciler())->reconcile($known, $this->report([ModelTest::finding('a/a', Severity::Critical)]))->isEmpty());
    }

    public function testUnacknowledgedNewFindingsAreNewAgainNextTime(): void
    {
        $reconciler = new Reconciler();
        $report = $this->report([ModelTest::finding('a/a'), ModelTest::finding('b/b')]);

        // The alert for b/b couldn't be delivered.
        $next = $reconciler->next([], $report, [$this->key('b/b')]);

        $this->assertSame([$this->key('a/a') => false], $next);
        $this->assertSame(['b/b'], array_map(fn (Finding $f): string => $f->package, $reconciler->reconcile($next, $report)->new));
    }

    public function testAnUnacknowledgedExploitedFlipIsNewsAgain(): void
    {
        $reconciler = new Reconciler();
        $known = [$this->key('a/a') => false];
        $report = $this->report([ModelTest::finding('a/a', kev: ModelTest::kev())]);

        $next = $reconciler->next($known, $report, [$this->key('a/a') => true]);

        $this->assertSame($known, $next, 'left as it was');
        $this->assertCount(1, $reconciler->reconcile($next, $report)->exploited);
    }

    public function testAnUnacknowledgedResolutionIsResolvedAgain(): void
    {
        $reconciler = new Reconciler();
        $known = [$this->key('a/a') => true, $this->key('b/b') => false];
        $report = $this->report([ModelTest::finding('b/b')]);

        $next = $reconciler->next($known, $report, [$this->key('a/a')]);

        $this->assertEquals($known, $next);
        $this->assertSame([$this->key('a/a')], $reconciler->reconcile($next, $report)->resolved);
    }

    public function testWithoutUnacknowledgedKeysNextIsUnchanged(): void
    {
        $known = [$this->key('a/a') => true];
        $report = $this->report([ModelTest::finding('b/b')]);

        $this->assertSame((new Reconciler())->next($known, $report), (new Reconciler())->next($known, $report, []));
    }

    public function testResolvedFindingsCarryWhatTheyWereLastSeenAs(): void
    {
        $reconciler = new Reconciler();
        $first = $this->report([ModelTest::finding('a/a', kev: ModelTest::kev()), ModelTest::finding('b/b', Severity::Low)]);
        $known = $reconciler->next([], $first);
        $lastSeen = $reconciler->lastSeen([], $first, $known);

        // What an adapter stores and reads back: plain arrays.
        $lastSeen = json_decode((string) json_encode($lastSeen), true);
        $this->assertIsArray($lastSeen);

        $changes = $reconciler->reconcile($known, $this->report([ModelTest::finding('b/b', Severity::Low)]), $lastSeen);

        $this->assertSame([$this->key('a/a')], $changes->resolved, 'the 1.0 field is unchanged');
        $resolved = $changes->resolvedFinding($this->key('a/a'));
        $this->assertNotNull($resolved);
        $this->assertSame('a/a', $resolved->package);
        $this->assertSame('Title', $resolved->title);
        $this->assertSame(Severity::High, $resolved->severity);
        $this->assertTrue($resolved->isExploited());
        $this->assertNull($changes->resolvedFinding($this->key('b/b')));
    }

    public function testLastSeenKeepsWhatAnIncompleteReportCouldNotVouchFor(): void
    {
        $reconciler = new Reconciler();
        $first = $this->report([ModelTest::finding('a/a'), ModelTest::finding('b/b')]);
        $lastSeen = $reconciler->lastSeen([], $first, $reconciler->next([], $first));

        $partial = $this->report([ModelTest::finding('b/b', Severity::Critical)], problems: ['OSV failed']);
        $next = $reconciler->next($reconciler->next([], $first), $partial);
        $kept = $reconciler->lastSeen($lastSeen, $partial, $next);

        $this->assertSame([$this->key('a/a'), $this->key('b/b')], array_keys($kept));
        $this->assertSame('critical', $kept[$this->key('b/b')]['severity'], 'refreshed from this report');
        $this->assertSame('high', $kept[$this->key('a/a')]['severity'], 'kept as last seen');
    }

    public function testAResolvedKeyWithoutStoredDataStillResolves(): void
    {
        $changes = (new Reconciler())->reconcile([$this->key('a/a') => false], $this->report([]), ['other' => ['broken']]);

        $this->assertSame([$this->key('a/a')], $changes->resolved);
        $this->assertSame([], $changes->resolvedFindings);
    }
}
