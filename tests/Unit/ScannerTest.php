<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Advisory;
use Ruvelo\SecurityAdvisories\AdvisoryMatch;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Ruvelo\SecurityAdvisories\Reconciler;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\AdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Tests\Support\ArrayCache;
use Ruvelo\SecurityAdvisories\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Threshold;

class ScannerTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../fixtures';

    private MockClient $client;

    protected function setUp(): void
    {
        $this->client = MockClient::feeds();
    }

    protected function tearDown(): void
    {
        $this->assertSame([], $this->client->stray, 'A request nobody expected');
    }

    private function http(): JsonClient
    {
        $factory = new Psr17Factory();

        return new JsonClient($this->client, $factory, $factory);
    }

    /**
     * Halyard's lockfiles the way the Laravel package scans them: production Composer packages, all npm packages.
     */
    private function halyard(): Scanner
    {
        $http = $this->http();

        return new Scanner(
            [new ComposerLockReader(self::FIXTURES.'/composer.lock', includeDev: false), new NpmLockReader(self::FIXTURES.'/package-lock.json')],
            [new PackagistAdvisorySource($http), new OsvSource($http)],
            new KevCatalogue($http),
        );
    }

    public function testItFindsTheHalyardVulnerabilitiesExploitedFirst(): void
    {
        $report = $this->halyard()->scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame(['composer' => 67, 'npm' => 38], $report->packages);
        $this->assertSame([Ecosystem::Composer, Ecosystem::Npm], $report->checked);
        $this->assertTrue($report->kevChecked);
        $this->assertCount(13, $report->findings);
        $this->assertSame(['exploited' => 1, 'critical' => 2, 'high' => 4, 'medium' => 5, 'low' => 1], $report->counts());

        $first = $report->findings[0];
        $this->assertSame('livewire/livewire', $first->package);
        $this->assertSame('3.6.2', $first->installed);
        $this->assertSame('3.6.4', $first->fixedIn);
        $this->assertSame('CVE-2025-54068', $first->cve);
        $this->assertSame(Severity::Critical, $first->severity);
        $this->assertTrue($first->isExploited());
        $this->assertSame('2026-03-20', $first->exploited?->dateAdded->format('Y-m-d'));
        $this->assertSame('2026-04-03', $first->exploited->dueDate?->format('Y-m-d'));
        $this->assertSame('https://github.com/advisories/GHSA-29cq-5w36-x7w3', $first->link);
        $this->assertSame($first, $report->worst());

        $this->assertSame(
            ['livewire/livewire', 'form-data', 'predis/predis', 'form-data', 'guzzlehttp/guzzle', 'maatwebsite/excel', 'vite', 'guzzlehttp/guzzle', 'laravel/framework', 'livewire/livewire', 'symfony/http-foundation', 'vite', 'laravel/framework'],
            array_map(fn (Finding $f): string => $f->package, $report->findings),
        );

        $formData = $report->findings[1];
        $this->assertSame(Ecosystem::Npm, $formData->ecosystem);
        $this->assertSame('4.0.4', $formData->fixedIn);
        $this->assertTrue($formData->isDev);
        $this->assertFalse($formData->isExploited());

        $this->assertTrue($report->failsOn(Threshold::Exploited));
    }

    public function testForProjectReadsBothLockfilesAndFlagsDevPackages(): void
    {
        $report = Scanner::forProject(self::FIXTURES, $this->http())->scan();

        $this->assertSame(['composer' => 73, 'npm' => 38], $report->packages);
        $this->assertTrue($report->isComplete());
        $this->assertGreaterThanOrEqual(13, count($report->findings));

        $withoutDev = Scanner::forProject(self::FIXTURES, $this->http(), includeDev: false)->scan();
        $this->assertSame(67, $withoutDev->packageCount(Ecosystem::Composer));
    }

    public function testOnlyNamesAreSentToPackagistAndNoVersionsAnywhereElseThanOsv(): void
    {
        $this->halyard()->scan();

        $packagist = $this->client->sentTo('packagist.org');
        $this->assertCount(1, $packagist);
        foreach (explode('&', (string) $packagist[0]->getBody()) as $pair) {
            $this->assertMatchesRegularExpression('#^packages\[\]=[A-Za-z0-9._%-]+$#', $pair, 'Package names and nothing else');
        }
        $this->assertStringContainsString('livewire%2Flivewire', (string) $packagist[0]->getBody());
        $this->assertStringNotContainsString('phpunit', (string) $packagist[0]->getBody(), 'Dev packages are left out when asked');

        $kev = $this->client->sentTo('cisa.gov');
        $this->assertCount(1, $kev);
        $this->assertSame('GET', $kev[0]->getMethod());
        $this->assertSame('', (string) $kev[0]->getBody());
    }

    public function testASecondScanComesFromTheCache(): void
    {
        $cache = new ArrayCache();
        $scanner = Scanner::forProject(self::FIXTURES, $this->http(), $cache);

        $scanner->scan();
        $sent = count($this->client->requests);
        $again = $scanner->scan();

        $this->assertSame($sent, count($this->client->requests));
        $this->assertTrue($again->isComplete());

        $scanner->scan(fresh: true);
        $this->assertGreaterThan($sent, count($this->client->requests));
    }

    public function testAMissingComposerLockIsAProblemButAMissingPackageLockIsNot(): void
    {
        $dir = sys_get_temp_dir().'/advisories-'.bin2hex(random_bytes(4));
        mkdir($dir);

        $report = Scanner::forProject($dir, $this->http())->scan();
        rmdir($dir);

        $this->assertSame([], $report->findings);
        $this->assertFalse($report->isComplete());
        $this->assertCount(1, $report->problems);
        $this->assertStringContainsString('composer.lock', $report->problems[0]);
        $this->assertSame([], $report->checked);
        $this->assertCount(0, $this->client->requests);
    }

    public function testAnUnreadableLockfileIsAProblem(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'lock');
        $this->assertIsString($path);
        file_put_contents($path, '{nope');
        $scanner = new Scanner([new ComposerLockReader($path)], [new PackagistAdvisorySource($this->http())]);

        $report = $scanner->scan();
        unlink($path);

        $this->assertFalse($report->isComplete());
        $this->assertStringContainsString('isn\'t valid JSON', $report->problems[0]);
        $this->assertStringContainsString('Composer packages weren\'t checked', $report->problems[0]);
    }

    public function testAFeedThatFailsLeavesItsEcosystemUnchecked(): void
    {
        $this->client = MockClient::feeds();
        $failing = new MockClient();
        $failing->on('POST', 'packagist.org', $failing->json([], 503));
        $failing->on('POST', 'querybatch', $this->client->fixture('osv-querybatch.json'));
        $failing->on('GET', '/vulns/', fn ($r) => $this->client->json((string) file_get_contents(self::FIXTURES.'/osv/'.basename($r->getUri()->getPath()).'.json')));
        $failing->on('GET', 'cisa.gov', $this->client->fixture('kev.json'));
        $this->client = $failing;

        $report = $this->halyard()->scan();

        $this->assertFalse($report->isComplete());
        $this->assertSame([Ecosystem::Npm], $report->checked, 'Composer was not checked in full');
        $this->assertStringContainsString('Packagist couldn\'t be reached', $report->problems[0]);
        $this->assertStringContainsString('Composer packages weren\'t checked', $report->problems[0]);
        $this->assertNotSame([], $report->findings, 'npm findings still come through');
    }

    public function testWhenKevFailsFindingsAreNotMarkedAndTheReportIsIncomplete(): void
    {
        $this->client = MockClient::feeds();
        $client = new MockClient();
        $client->on('POST', 'packagist.org', $this->client->fixture('packagist.json'));
        $client->on('GET', 'cisa.gov', new \Nyholm\Psr7\Response(500));
        $this->client = $client;
        $http = $this->http();
        $scanner = new Scanner([new ComposerLockReader(self::FIXTURES.'/composer.lock', false)], [new PackagistAdvisorySource($http)], new KevCatalogue($http));

        $report = $scanner->scan();

        $this->assertFalse($report->kevChecked);
        $this->assertFalse($report->isComplete());
        $this->assertSame([], $report->exploited());
        $this->assertSame([Ecosystem::Composer], $report->checked);
        $this->assertStringContainsString('aren\'t marked as exploited', $report->problems[0]);
        $this->assertNotSame([], $report->findings);
    }

    public function testAnIncompleteScanNeverResolvesWhatItDidNotSee(): void
    {
        $full = $this->halyard()->scan();
        $known = (new Reconciler())->next([], $full);

        $empty = new Scanner([new ComposerLockReader('/nowhere/composer.lock')], [new PackagistAdvisorySource($this->http())]);
        $report = $empty->scan();

        $this->assertSame([], (new Reconciler())->reconcile($known, $report)->resolved);
        $this->assertTrue((new Reconciler())->reconcile($known, $full)->isEmpty());
    }

    public function testAnEcosystemWithoutASourceIsInventoriedNotAProblem(): void
    {
        $scanner = new Scanner([new ExtensionList([['name' => 'com_x', 'version' => '1.0.0']])], [new PackagistAdvisorySource($this->http())]);

        $report = $scanner->scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame([], $report->problems);
        $this->assertSame([], $report->checked);
        $this->assertCount(1, $report->unchecked);
        $this->assertSame('com_x', $report->unchecked[0]->package->name);
        $this->assertStringContainsString('No advisory source covers extension packages', $report->unchecked[0]->reason);
    }

    public function testAPlatformPlugsInItsOwnInventoryAndAdvisorySource(): void
    {
        $source = new class () implements AdvisorySource {
            public function supports(Ecosystem $ecosystem): bool
            {
                return $ecosystem === Ecosystem::Extension;
            }

            public function find(array $packages, bool $fresh = false): array
            {
                $matches = [];
                foreach ($packages as $package) {
                    if ($package->name === 'com_akeeba' && version_compare($package->version, '9.2.0', '<')) {
                        $matches[] = new AdvisoryMatch($package, new Advisory('JVD-1', Ecosystem::Extension, 'com_akeeba', 'Akeeba flaw', cve: 'CVE-2025-54068', severity: Severity::High), '9.2.0');
                    }
                }

                return $matches;
            }
        };
        $http = $this->http();
        $scanner = new Scanner(
            [new ExtensionList([['name' => 'com_akeeba', 'version' => '9.1.0'], ['name' => 'com_other', 'version' => '1.0.0']], label: 'the Joomla extension list')],
            [$source],
            new KevCatalogue($http),
        );

        $report = $scanner->scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame([Ecosystem::Extension], $report->checked);
        $this->assertSame(['extension' => 2], $report->packages);
        $this->assertCount(1, $report->findings);
        $this->assertSame('extension:com_akeeba:JVD-1', $report->findings[0]->key());
        $this->assertSame('9.2.0', $report->findings[0]->fixedIn);
        $this->assertTrue($report->findings[0]->isExploited(), 'KEV applies to any source\'s CVEs');
    }

    public function testTheSameAdvisoryOnTwoCopiesIsReportedOnce(): void
    {
        $source = new class () implements AdvisorySource {
            public function supports(Ecosystem $ecosystem): bool
            {
                return $ecosystem === Ecosystem::Npm;
            }

            public function find(array $packages, bool $fresh = false): array
            {
                $advisory = new Advisory('GHSA-1', Ecosystem::Npm, 'x', 'Flaw');

                return array_map(fn (InstalledPackage $p): AdvisoryMatch => new AdvisoryMatch($p, $advisory), $packages);
            }
        };
        $scanner = new Scanner([new ExtensionList([new InstalledPackage(Ecosystem::Npm, 'x', '1.0.0'), new InstalledPackage(Ecosystem::Npm, 'x', '1.0.0')], Ecosystem::Npm)], [$source]);

        $this->assertCount(1, $scanner->scan()->findings);
    }
}
