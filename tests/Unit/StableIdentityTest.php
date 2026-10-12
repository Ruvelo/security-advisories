<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use DateTimeImmutable;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\KevEntry;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Tests\Support\StubSource;

class StableIdentityTest extends TestCase
{
    private InstalledPackage $package;

    protected function setUp(): void
    {
        $this->package = new InstalledPackage(Ecosystem::Composer, 'acme/lib', '1.0.0');
    }

    /**
     * @param list<string> $aliases
     */
    private function advisory(string $id, ?string $cve, array $aliases = [], ?string $constraint = null, ?KevEntry $kev = null): AdvisoryMatch
    {
        return new AdvisoryMatch($this->package, new Advisory($id, Ecosystem::Composer, 'acme/lib', 'T', cve: $cve, affectedVersions: $constraint, kev: $kev, kevKnown: $kev !== null, aliases: $aliases));
    }

    /**
     * @param list<AdvisoryMatch> $matches
     */
    private function report(array $matches): Report
    {
        return (new Scanner([new ExtensionList([$this->package], Ecosystem::Composer)], [new StubSource([Ecosystem::Composer], fn (): array => $matches)]))->scan();
    }

    /**
     * Stores a report the way an adapter would, then reconciles another against it.
     *
     * @return array{\Ruvelo\SecurityAdvisories\Changes, array<string, bool>}
     */
    private function second(Report $first, Report $second, bool $keepLastSeen = true): array
    {
        $r = new Reconciler();
        $known = $r->next([], $first);
        $lastSeen = $keepLastSeen ? $r->lastSeen([], $first, $known) : [];

        return [$r->reconcile($known, $second, $lastSeen), $r->next($known, $second, [], $lastSeen)];
    }

    public function testAltKeysCoverIdCveAndAliases(): void
    {
        $finding = Finding::from($this->advisory('PKSA-1', 'CVE-2026-0001', ['ghsa-abcd', 'SA-1']));

        $this->assertSame('composer:acme/lib:PKSA-1', $finding->key());
        $this->assertEqualsCanonicalizing([
            'composer:acme/lib:PKSA-1', 'composer:acme/lib:CVE-2026-0001', 'composer:acme/lib:ghsa-abcd', 'composer:acme/lib:GHSA-ABCD', 'composer:acme/lib:SA-1',
        ], $finding->altKeys());
    }

    public function testSwitchingFromValtryToThePublicFeedsIsNotNewAndNotResolved(): void
    {
        $valtry = $this->report([$this->advisory('GHSA-1', 'CVE-2026-0001')]);
        $public = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001', constraint: '<2.0.0')]);

        [$changes, $next] = $this->second($valtry, $public);

        $this->assertTrue($changes->isEmpty());
        $this->assertSame([], $changes->resolved);
        $this->assertSame(['composer:acme/lib:GHSA-1' => false], $next, 'the stored identity does not churn');
    }

    public function testADedupeWinnerThatFlipsIsNotNewAndNotResolvedEvenWithoutLastSeen(): void
    {
        $both = fn (bool $exactFirst): Report => $this->report([
            $this->advisory('PKSA-1', 'CVE-2026-0001', constraint: $exactFirst ? '<2.0.0' : null),
            $this->advisory('GHSA-1', 'CVE-2026-0001', constraint: $exactFirst ? null : '<2.0.0'),
        ]);

        $first = $both(true);
        $second = $both(false);
        $this->assertSame('PKSA-1', $first->findings[0]->advisoryId);
        $this->assertSame('GHSA-1', $second->findings[0]->advisoryId);

        foreach ([true, false] as $keepLastSeen) {
            [$changes, $next] = $this->second($first, $second, $keepLastSeen);

            $this->assertTrue($changes->isEmpty());
            $this->assertSame(['composer:acme/lib:PKSA-1' => false], $next);
        }
    }

    public function testAOneZeroKnownSetStillMatches(): void
    {
        $report = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001')]);
        $known = ['composer:acme/lib:PKSA-1' => false];
        $r = new Reconciler();

        $this->assertTrue($r->reconcile($known, $report)->isEmpty());
        $this->assertSame($known, $r->next($known, $report));
        $this->assertSame(['composer:acme/lib:PKSA-1'], array_keys($r->lastSeen([], $report, $known)));
    }

    public function testAKnownSetKeyedByAnAliasMatchesTheCurrentFinding(): void
    {
        $report = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001', ['GHSA-1'])]);
        $known = ['composer:acme/lib:GHSA-1' => false];

        $changes = (new Reconciler())->reconcile($known, $report);

        $this->assertTrue($changes->isEmpty());
        $this->assertSame($known, (new Reconciler())->next($known, $report));
    }

    public function testAnExploitedFlagSetUnderTheOldKeyCarriesOver(): void
    {
        $kev = new KevEntry('CVE-2026-0001', 'Boom', new DateTimeImmutable('2026-02-01'), null, false);
        $report = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001', ['GHSA-1'], kev: $kev)]);
        $r = new Reconciler();

        $alreadyExploited = ['composer:acme/lib:GHSA-1' => true];
        $this->assertSame([], $r->reconcile($alreadyExploited, $report)->exploited, 'not news again');
        $this->assertSame(['composer:acme/lib:GHSA-1' => true], $r->next($alreadyExploited, $report));

        $notYet = ['composer:acme/lib:GHSA-1' => false];
        $this->assertCount(1, $r->reconcile($notYet, $report)->exploited, 'a flip is news');

        $later = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001', ['GHSA-1'])]);
        $this->assertSame(['composer:acme/lib:GHSA-1' => true], $r->next($alreadyExploited, $later), 'never lowered');
    }

    public function testOnlyEntriesNothingMatchesAreResolved(): void
    {
        $report = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001', ['GHSA-1'])]);
        $known = ['composer:acme/lib:GHSA-1' => false, 'composer:acme/lib:CVE-2026-0001' => false, 'composer:acme/lib:OTHER-9' => true];
        $r = new Reconciler();

        $this->assertSame(['composer:acme/lib:OTHER-9'], $r->reconcile($known, $report)->resolved);
        $this->assertSame(['composer:acme/lib:GHSA-1' => false], $r->next($known, $report), 'two old entries for one vulnerability collapse into the first');
    }

    public function testAnUnacknowledgedCurrentKeyHoldsTheStoredEntry(): void
    {
        $first = $this->report([$this->advisory('GHSA-1', 'CVE-2026-0001')]);
        $kev = new KevEntry('CVE-2026-0001', 'Boom', new DateTimeImmutable('2026-02-01'), null, false);
        $second = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001', kev: $kev)]);
        $r = new Reconciler();
        $known = $r->next([], $first);
        $lastSeen = $r->lastSeen([], $first, $known);

        $changes = $r->reconcile($known, $second, $lastSeen);
        $this->assertCount(1, $changes->exploited);

        $next = $r->next($known, $second, [$changes->exploited[0]->key()], $lastSeen);
        $this->assertSame(['composer:acme/lib:GHSA-1' => false], $next, 'undelivered, so still news next time');
    }

    public function testLastSeenFollowsTheStoredKey(): void
    {
        $first = $this->report([$this->advisory('GHSA-1', 'CVE-2026-0001')]);
        $second = $this->report([$this->advisory('PKSA-1', 'CVE-2026-0001')]);
        $r = new Reconciler();
        $known = $r->next([], $first);
        $lastSeen = $r->lastSeen([], $first, $known);
        $next = $r->next($known, $second, [], $lastSeen);

        $again = $r->lastSeen($lastSeen, $second, $next);

        $this->assertSame(['composer:acme/lib:GHSA-1'], array_keys($again));
        $this->assertSame('PKSA-1', $again['composer:acme/lib:GHSA-1']['advisory_id']);
    }
}
