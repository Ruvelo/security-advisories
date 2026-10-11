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
}
