<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Ruvelo\SecurityAdvisories\Severity;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Tests\Support\ArrayCache;
use Ruvelo\SecurityAdvisories\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Tests\Support\NetworkError;

class SourcesTest extends TestCase
{
    private MockClient $client;

    protected function setUp(): void
    {
        $this->client = MockClient::feeds();
    }

    protected function tearDown(): void
    {
        $this->assertSame([], $this->client->stray, 'A request nobody expected');
    }

    private function http(int $tries = 2): JsonClient
    {
        $factory = new \Nyholm\Psr7\Factory\Psr17Factory();

        return new JsonClient($this->client, $factory, $factory, tries: $tries);
    }

    private function composer(string $name, string $version): InstalledPackage
    {
        return new InstalledPackage(Ecosystem::Composer, $name, $version);
    }

    public function testPackagistSendsNamesOnlyAndMatchesVersionsLocally(): void
    {
        $source = new PackagistAdvisorySource($this->http());

        $matches = $source->find([$this->composer('livewire/livewire', '3.6.2'), $this->composer('livewire/livewire-nope', '1.0.0'), $this->composer('livewire/livewire', '3.6.4')]);

        $this->assertNotSame([], $matches);
        $this->assertSame(['livewire/livewire'], array_values(array_unique(array_map(fn ($m): string => $m->package->name, $matches))));
        $rce = array_values(array_filter($matches, fn ($m): bool => $m->advisory->cve === 'CVE-2025-54068'));
        $this->assertCount(1, $rce, '3.6.4, the fixed release, is not affected by it');
        $this->assertSame('3.6.2', $rce[0]->package->version);
        $rce = $rce[0];
        $this->assertSame('3.6.4', $rce->fixedIn);
        $this->assertSame(Severity::Critical, $rce->advisory->severity);

        $requests = $this->client->sentTo('packagist.org');
        $this->assertCount(1, $requests);
        $this->assertSame('POST', $requests[0]->getMethod());
        $this->assertSame('application/x-www-form-urlencoded', $requests[0]->getHeaderLine('Content-Type'));
        $this->assertStringStartsWith('ruvelo/security-advisories', $requests[0]->getHeaderLine('User-Agent'));
        $body = (string) $requests[0]->getBody();
        $this->assertSame('packages[]=livewire%2Flivewire&packages[]=livewire%2Flivewire-nope', $body, 'Names only, sorted, no versions');
    }

    public function testPackagistBatchesNames(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'packagist.org', $this->client->json(['advisories' => []]));
        $names = array_map(fn (int $i): string => sprintf('vendor/pkg-%03d', $i), range(1, 450));

        (new PackagistAdvisorySource($this->http()))->advisories($names);

        $this->assertCount(3, $this->client->sentTo('packagist.org'));
    }

    public function testPackagistIgnoresMalformedAdvisories(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'packagist.org', $this->client->json(['advisories' => [
            'a/a' => [['advisoryId' => 'PKSA-1', 'title' => 'ok', 'affectedVersions' => '<2.0'], ['title' => 'no id', 'affectedVersions' => '<2.0'], 'junk'],
            'b/b' => 'junk',
        ]]));

        $found = (new PackagistAdvisorySource($this->http()))->advisories(['a/a', 'b/b']);

        $this->assertSame(['a/a'], array_keys($found));
        $this->assertCount(1, $found['a/a']);
    }

    public function testPackagistTitleRepeatingTheCveIsTrimmed(): void
    {
        $advisory = PackagistAdvisorySource::advisory('symfony/http-foundation', [
            'advisoryId' => 'PKSA-1', 'affectedVersions' => '<7.4.13', 'title' => 'CVE-2026-48736: IpUtils omits IPv6 forms',
            'cve' => 'cve-2026-48736', 'severity' => null, 'link' => '',
        ]);

        $this->assertSame('IpUtils omits IPv6 forms', $advisory?->title);
        $this->assertSame('CVE-2026-48736', $advisory->cve);
        $this->assertSame(Severity::NotRated, $advisory->severity);
        $this->assertNull($advisory->link);
    }

    public function testPackagistFailuresAreSourceUnavailable(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'packagist.org', $this->client->json('nope', 200));

        try {
            (new PackagistAdvisorySource($this->http()))->find([$this->composer('a/a', '1.0.0')]);
            $this->fail('No exception');
        } catch (SourceUnavailable $e) {
            $this->assertSame('Packagist', $e->source);
            $this->assertStringContainsString('JSON', $e->getMessage());
        }
    }

    public function testAnErrorStatusIsSourceUnavailable(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'packagist.org', $this->client->json([], 503));

        $this->expectException(SourceUnavailable::class);
        $this->expectExceptionMessage('HTTP 503');
        (new PackagistAdvisorySource($this->http()))->find([$this->composer('a/a', '1.0.0')]);
    }

    public function testATransientFailureIsRetried(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'packagist.org', $this->client->json([], 502), $this->client->json(['advisories' => []]));

        $this->assertSame([], (new PackagistAdvisorySource($this->http()))->find([$this->composer('a/a', '1.0.0')]));
        $this->assertCount(2, $this->client->requests);
    }

    public function testAConnectionErrorIsRetriedThenReported(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'packagist.org', new NetworkError(new \Nyholm\Psr7\Request('POST', 'https://packagist.org')));

        try {
            (new PackagistAdvisorySource($this->http(tries: 3)))->find([$this->composer('a/a', '1.0.0')]);
            $this->fail('No exception');
        } catch (SourceUnavailable $e) {
            $this->assertStringContainsString('connection refused', $e->getMessage());
            $this->assertCount(3, $this->client->requests);
        }
    }

    public function testResponsesAreCachedWithTheConfiguredLifetime(): void
    {
        $cache = new ArrayCache();
        $source = new PackagistAdvisorySource($this->http(), new ResponseCache($cache, new Ttls(advisories: 900)));
        $packages = [$this->composer('livewire/livewire', '3.6.2')];

        $first = $source->find($packages);
        $second = $source->find($packages);

        $this->assertEquals($first, $second);
        $this->assertCount(1, $this->client->requests, 'The second call came from the cache');
        $this->assertSame([900], array_values($cache->ttls));
        foreach (array_keys($cache->items) as $key) {
            $this->assertDoesNotMatchRegularExpression('/[{}()\/\\\\@:]/', $key, 'PSR-16 reserves these characters');
        }

        $source->find($packages, fresh: true);
        $this->assertCount(2, $this->client->requests, 'fresh skips the cache');
    }

    public function testACacheOfZeroLifetimeIsOff(): void
    {
        $cache = new ArrayCache();
        $source = new PackagistAdvisorySource($this->http(), new ResponseCache($cache, new Ttls(advisories: 0)));

        $source->find([$this->composer('livewire/livewire', '3.6.2')]);
        $source->find([$this->composer('livewire/livewire', '3.6.2')]);

        $this->assertSame([], $cache->items);
        $this->assertCount(2, $this->client->requests);
    }

    public function testDefaultLifetimesMatchTheLaravelPackage(): void
    {
        $ttls = new Ttls();

        $this->assertSame([3600, 21600, 604800], [$ttls->advisories, $ttls->kev, $ttls->osvDetails]);
    }

    public function testOsvFindsNpmAdvisories(): void
    {
        $npm = (new NpmLockReader(__DIR__.'/../fixtures/package-lock.json'))->packages() ?? [];

        $matches = (new OsvSource($this->http()))->find($npm);

        $this->assertNotSame([], $matches);
        $ids = array_map(fn ($m): string => $m->advisory->id, $matches);
        $this->assertContains('GHSA-fx2h-pf6j-xcff', $ids);

        $vite = array_values(array_filter($matches, fn ($m): bool => $m->advisory->id === 'GHSA-fx2h-pf6j-xcff'))[0];
        $this->assertSame('vite', $vite->package->name);
        $this->assertSame('CVE-2026-53571', $vite->advisory->cve);
        $this->assertSame(Severity::High, $vite->advisory->severity);
        $this->assertSame('https://github.com/advisories/GHSA-fx2h-pf6j-xcff', $vite->advisory->link);
        $this->assertNotNull($vite->fixedIn);

        $query = json_decode((string) $this->client->sentTo('/querybatch')[0]->getBody(), true);
        $this->assertIsArray($query);
        $this->assertSame(['queries'], array_keys($query));
        $this->assertSame(['package', 'version'], array_keys($query['queries'][0]));
        $this->assertSame(['name', 'ecosystem'], array_keys($query['queries'][0]['package']));
    }

    public function testOsvDetailsAreFetchedOnceAndCached(): void
    {
        $npm = (new NpmLockReader(__DIR__.'/../fixtures/package-lock.json'))->packages() ?? [];
        $cache = new ResponseCache(new ArrayCache());
        $source = new OsvSource($this->http(), $cache);

        $source->find($npm);
        $sent = count($this->client->requests);
        $source->find($npm);

        $this->assertSame($sent, count($this->client->requests));
    }

    public function testOsvFailsWhenDetailsCannotBeFetched(): void
    {
        $this->client = new MockClient();
        $this->client->on('POST', 'querybatch', $this->client->json(['results' => [['vulns' => [['id' => 'GHSA-x', 'modified' => '2026-01-01T00:00:00Z']]]]]));
        $this->client->on('GET', '/vulns/', $this->client->json([], 500));

        $this->expectException(SourceUnavailable::class);
        (new OsvSource($this->http(tries: 1)))->find([new InstalledPackage(Ecosystem::Npm, 'x', '1.0.0')]);
    }

    public function testOsvIgnoresOtherEcosystems(): void
    {
        $source = new OsvSource($this->http());

        $this->assertSame([], $source->find([$this->composer('a/a', '1.0.0')]));
        $this->assertTrue($source->supports(Ecosystem::Npm));
        $this->assertFalse($source->supports(Ecosystem::Composer));
        $this->assertCount(0, $this->client->requests);
    }

    public function testKevMarksListedCves(): void
    {
        $found = (new KevCatalogue($this->http()))->lookup(['cve-2025-54068', 'CVE-1999-0001']);

        $this->assertSame(['CVE-2025-54068'], array_keys($found));
        $this->assertSame('2026-03-20', $found['CVE-2025-54068']->dateAdded->format('Y-m-d'));
        $this->assertSame('2026-04-03', $found['CVE-2025-54068']->dueDate?->format('Y-m-d'));
    }

    public function testKevIsNotDownloadedWithoutCves(): void
    {
        $this->assertSame([], (new KevCatalogue($this->http()))->lookup([]));
        $this->assertCount(0, $this->client->requests);
    }

    public function testKevCataloguePeekIsCachedForSixHours(): void
    {
        $cache = new ArrayCache();
        $kev = new KevCatalogue($this->http(), new ResponseCache($cache));

        $kev->lookup(['CVE-2025-54068']);
        $kev->lookup(['CVE-2025-54068']);

        $this->assertCount(1, $this->client->requests);
        $this->assertSame([21600], array_values($cache->ttls));
    }

    public function testKevWithoutAListIsUnavailable(): void
    {
        $this->client = new MockClient();
        $this->client->on('GET', 'cisa.gov', $this->client->json(['title' => 'oops']));

        $this->expectException(SourceUnavailable::class);
        (new KevCatalogue($this->http()))->lookup(['CVE-2025-54068']);
    }

    public function testWithoutAnHttpClientTheErrorSaysWhatToInstall(): void
    {
        try {
            \Http\Discovery\Psr18ClientDiscovery::find();
            $this->markTestSkipped('A PSR-18 client is installed here.');
        } catch (\Throwable) {
        }

        try {
            (new JsonClient())->get('Test', 'https://example.com');
            $this->fail('No exception');
        } catch (SourceUnavailable $e) {
            $this->assertStringContainsString('PSR-18 client', $e->getMessage());
            $this->assertCount(0, $this->client->requests);
        }
    }
}
