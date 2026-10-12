<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\RequestInterface;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Finding;
use Ruvelo\SecurityAdvisories\Http\JsonClient;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;
use Ruvelo\SecurityAdvisories\Report;
use Ruvelo\SecurityAdvisories\Scanner;
use Ruvelo\SecurityAdvisories\Sources\FallbackAdvisorySource;
use Ruvelo\SecurityAdvisories\Sources\KevCatalogue;
use Ruvelo\SecurityAdvisories\Sources\OsvSource;
use Ruvelo\SecurityAdvisories\Sources\PackagistAdvisorySource;
use Ruvelo\SecurityAdvisories\Tests\Support\ArrayCache;
use Ruvelo\SecurityAdvisories\Tests\Support\MockClient;
use Ruvelo\SecurityAdvisories\Tests\Support\NetworkError;
use Ruvelo\SecurityAdvisories\Tests\Support\ValtryServer;
use Ruvelo\SecurityAdvisories\Valtry\Keys;
use Ruvelo\SecurityAdvisories\Valtry\ValtryAdvisorySource;

class ValtrySourceTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../fixtures';

    private MockClient $client;

    private ValtryServer $valtry;

    protected function setUp(): void
    {
        $this->client = MockClient::feeds();
        $this->valtry = new ValtryServer($this->client);
        $this->client->on('POST', 'valtry.test', fn (RequestInterface $request) => $this->valtry->respond($request));
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
     * Halyard's lockfiles, Valtry first (with the test key pinned unless told otherwise), then the public feeds.
     *
     * @param array<string, string>|null $keys
     */
    private function scanner(?array $keys = null, ?ArrayCache $cache = null): Scanner
    {
        $http = $this->http();
        $responses = new ResponseCache($cache);

        return new Scanner(
            [new ComposerLockReader(self::FIXTURES.'/composer.lock', includeDev: false), new NpmLockReader(self::FIXTURES.'/package-lock.json')],
            [new FallbackAdvisorySource(
                new ValtryAdvisorySource($http, $responses, ValtryServer::URL, $keys ?? $this->valtry->keys()),
                [new PackagistAdvisorySource($http, $responses), new OsvSource($http, $responses)],
            )],
            new KevCatalogue($http, $responses),
        );
    }

    private function publicScanner(): Scanner
    {
        $http = $this->http();

        return new Scanner(
            [new ComposerLockReader(self::FIXTURES.'/composer.lock', includeDev: false), new NpmLockReader(self::FIXTURES.'/package-lock.json')],
            [new PackagistAdvisorySource($http), new OsvSource($http)],
            new KevCatalogue($http),
        );
    }

    private function publicFeedsUsed(): bool
    {
        return $this->client->sentTo('packagist.org') !== [] || $this->client->sentTo('api.osv.dev') !== [];
    }

    public function testValtryAnswersBothEcosystemsInOneSignedRequestEach(): void
    {
        $report = $this->scanner()->scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame('valtry', $report->source);
        $this->assertSame(['composer' => 'valtry', 'npm' => 'valtry'], $report->sources);
        $this->assertCount(13, $report->findings);
        $this->assertTrue($report->findings[0]->isExploited(), 'the KEV verdict comes with the answer');
        $this->assertTrue($report->kevChecked);
        $this->assertCount(2, $this->client->sentTo('valtry.test'));
        $this->assertFalse($this->publicFeedsUsed());
        $this->assertSame([], $this->client->sentTo('cisa.gov'), 'no catalogue download when Valtry answered everything');
    }

    public function testOnlyNamesAndANonceAreSent(): void
    {
        $this->scanner()->scan();

        foreach ($this->valtry->received as $body) {
            $this->assertSame(['nonce', 'packages'], array_keys($body));
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{32}$/', $body['nonce']);
            foreach ($body['packages'] as $package) {
                $this->assertSame(['ecosystem', 'name'], array_keys($package));
            }
        }
        $this->assertNotSame($this->valtry->received[0]['nonce'], $this->valtry->received[1]['nonce']);
        $sent = implode("\n", array_map(fn (RequestInterface $r): string => (string) $r->getBody(), $this->client->sentTo('valtry.test')));
        $this->assertStringNotContainsString('3.6.2', $sent, 'livewire\'s installed version never leaves');
    }

    public function testBothPathsGiveTheSameFindings(): void
    {
        $viaValtry = $this->scanner()->scan();
        $viaPublic = $this->publicScanner()->scan();

        $strip = fn (Report $r): array => array_map(fn (Finding $f): array => $f->toArray(), $r->findings);
        $this->assertSame($strip($viaPublic), $strip($viaValtry));
        $this->assertSame($viaPublic->counts(), $viaValtry->counts());
        $this->assertSame('public', $viaPublic->source);
    }

    /**
     * @return array<string, array{callable(ValtryServer): void}>
     */
    public static function brokenAnswers(): array
    {
        return [
            'signed with another key' => [function (ValtryServer $v): void {
                $other = sodium_crypto_sign_secretkey(sodium_crypto_sign_keypair());
                $v->tamper = fn (array $answer, string $json): array => [$json, 'ed25519='.base64_encode(sodium_crypto_sign_detached($json, $other)).'; kid=test-1'];
            }],
            'body changed after signing' => [function (ValtryServer $v): void {
                $v->tamper = fn (array $answer, string $json): array => [str_replace('"exploited":true', '"exploited":false', $json), $v->sign($json)];
            }],
            'unknown kid' => [function (ValtryServer $v): void {
                $v->tamper = fn (array $answer, string $json): array => [$json, $v->sign($json, 'rogue')];
            }],
            'no signature' => [function (ValtryServer $v): void {
                $v->tamper = fn (array $answer, string $json): array => [$json, ''];
            }],
            'a replayed answer (other nonce)' => [function (ValtryServer $v): void {
                $v->tamper = function (array $answer, string $json) use ($v): array {
                    $answer['nonce'] = 'an-older-request-nonce-0000000000';
                    $json = (string) json_encode($answer, JSON_UNESCAPED_SLASHES);

                    return [$json, $v->sign($json)];
                };
            }],
            'packages left out' => [function (ValtryServer $v): void {
                $v->tamper = function (array $answer, string $json) use ($v): array {
                    $answer['advisories'] = new \stdClass();
                    $json = (string) json_encode($answer, JSON_UNESCAPED_SLASHES);

                    return [$json, $v->sign($json)];
                };
            }],
            'not json' => [function (ValtryServer $v): void {
                $v->tamper = fn (array $answer, string $json): array => ['<html>', $v->sign('<html>')];
            }],
        ];
    }

    /**
     * @param callable(ValtryServer): void $break
     */
    #[DataProvider('brokenAnswers')]
    public function testAnAnswerThatDoesNotVerifyFallsBackToThePublicFeeds(callable $break): void
    {
        $break($this->valtry);

        $report = $this->scanner()->scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame('public', $report->source);
        $this->assertCount(13, $report->findings);
        $this->assertTrue($this->publicFeedsUsed());
        $this->assertCount(1, $this->client->sentTo('valtry.test'), 'after one refused answer Valtry is left alone for the rest of the scan');
    }

    public function testATimeoutFallsBack(): void
    {
        $client = MockClient::feeds();
        $client->on('POST', 'valtry.test', fn (RequestInterface $r) => throw new NetworkError($r, 'Operation timed out after 5000 milliseconds'));
        $this->client = $client;

        $report = $this->scanner()->scan();

        $this->assertSame('public', $report->source);
        $this->assertTrue($report->isComplete());
        $this->assertCount(1, $client->sentTo('valtry.test'), 'one try, no retry, no second ecosystem');
    }

    /**
     * @return array<string, array{int}>
     */
    public static function errorStatuses(): array
    {
        return ['HTTP 500' => [500], 'HTTP 502' => [502], 'HTTP 503' => [503], 'HTTP 429' => [429], 'HTTP 400' => [400]];
    }

    #[DataProvider('errorStatuses')]
    public function testAnErrorStatusFallsBack(int $status): void
    {
        $client = MockClient::feeds();
        $client->on('POST', 'valtry.test', $client->json(['v' => 1, 'error' => 'unavailable'], $status));
        $this->client = $client;

        $report = $this->scanner()->scan();

        $this->assertSame('public', $report->source);
        $this->assertTrue($report->isComplete());
        $this->assertCount(1, $client->sentTo('valtry.test'));
    }

    public function testAFailureIsRememberedForFiveMinutes(): void
    {
        $cache = new ArrayCache();
        $this->valtry->tamper = fn (array $answer, string $json): array => [$json, ''];
        $this->scanner(cache: $cache)->scan();
        $this->assertCount(1, $this->client->sentTo('valtry.test'));

        $this->valtry->tamper = null;
        $this->scanner(cache: $cache)->scan(); // a new scanner, the same cache: Valtry is still skipped
        $this->assertCount(1, $this->client->sentTo('valtry.test'));

        $report = $this->scanner(cache: $cache)->scan(fresh: true); // a forced fresh check tries again
        $this->assertSame('valtry', $report->source);
    }

    public function testStaleDataForOneEcosystemFallsBackForThatEcosystemOnly(): void
    {
        $this->valtry->stale = ['npm'];

        $report = $this->scanner()->scan();

        $this->assertTrue($report->isComplete());
        $this->assertSame(['composer' => 'valtry', 'npm' => 'public'], $report->sources);
        $this->assertSame('mixed', $report->source);
        $this->assertSame([], $this->client->sentTo('packagist.org'));
        $this->assertNotSame([], $this->client->sentTo('api.osv.dev'));
        $this->assertCount(13, $report->findings);
        $this->assertSame(['composer' => 'valtry', 'npm' => 'public'], $report->toArray()['sources']);
    }

    public function testWithPlaceholderKeysNothingIsSentToValtry(): void
    {
        $this->assertTrue(Keys::hasPlaceholders() || Keys::decode() !== []);

        $report = $this->scanner(keys: ['valtry-1' => Keys::PLACEHOLDER])->scan();

        $this->assertSame([], $this->client->sentTo('valtry.test'));
        $this->assertSame('public', $report->source);
        $this->assertTrue($report->isComplete());
    }

    /**
     * @return array<string, string>
     */
    private static function pinned(): array
    {
        return Keys::PINNED;
    }

    public function testThePinnedKeysAreEitherPlaceholdersOrRealKeys(): void
    {
        foreach (self::pinned() as $kid => $key) {
            $this->assertMatchesRegularExpression('/^[A-Za-z0-9_-]{1,64}$/', $kid);
            if ($key !== Keys::PLACEHOLDER) {
                $this->assertArrayHasKey($kid, Keys::decode(), "{$kid} is not a base64 32-byte Ed25519 public key");
            }
        }
        $this->assertSame([], Keys::decode(['a' => 'not base64!', 'b' => base64_encode('short'), 'c' => Keys::PLACEHOLDER]));
    }

    public function testTheOptOutKeepsEveryScanOffValtry(): void
    {
        $this->assertSame('valtry', Scanner::source());
        $this->assertSame('public', Scanner::source('public'));
        $this->assertSame('valtry', Scanner::source('something-else'));

        putenv(Scanner::ENV.'=public');
        try {
            $this->assertSame('public', Scanner::source());
            $this->assertSame('public', Scanner::source('valtry'), 'the environment wins');
        } finally {
            putenv(Scanner::ENV);
        }

        $sources = fn (Scanner $s): array => (fn (): array => $this->advisorySources)->call($s);
        $optedOut = $sources(Scanner::forProject(self::FIXTURES, $this->http(), source: 'public'));
        $this->assertSame([PackagistAdvisorySource::class, OsvSource::class], array_map(fn (object $o): string => $o::class, $optedOut));
        $default = $sources(Scanner::forProject(self::FIXTURES, $this->http()));
        $this->assertInstanceOf(FallbackAdvisorySource::class, $default[0]);

        // And end to end: an opted-out scan never touches Valtry, even with a key that would verify.
        $this->assertSame('public', Scanner::forProject(self::FIXTURES, $this->http(), source: 'public', valtryUrl: ValtryServer::URL)->scan()->source);
        $this->assertSame([], $this->client->sentTo('valtry.test'));
    }

    public function testForProjectStillWorksTheOneOhWay(): void
    {
        // 1.0 adapters pass positional arguments only; with placeholder keys this is the public path, unchanged.
        $report = Scanner::forProject(self::FIXTURES, $this->http(), null, false)->scan();
        $public = Scanner::forProject(self::FIXTURES, $this->http(), null, false, source: 'public')->scan();

        $this->assertTrue($report->isComplete());
        $this->assertEquals($public->findings, $report->findings);
        if (Keys::hasPlaceholders()) {
            $this->assertSame('public', $report->source);
        }
    }

    public function testAdvisoriesMapOntoTheExistingModel(): void
    {
        $composer = ValtryAdvisorySource::advisory(Ecosystem::Composer, 'symfony/http-foundation', [
            'id' => 'PKSA-1', 'title' => 'CVE-2026-1: IpUtils bypass', 'cve' => 'cve-2026-1', 'severity' => 'high', 'affected' => '<6.4.1',
            'link' => 'https://x', 'published_at' => '2026-07-22T21:07:07Z', 'exploited' => true,
            'kev' => ['cve' => 'CVE-2026-1', 'name' => 'Symfony bypass', 'date_added' => '2026-08-01', 'due_date' => null, 'ransomware' => true],
        ]);
        $this->assertNotNull($composer);
        $this->assertSame('IpUtils bypass', $composer->title);
        $this->assertSame('CVE-2026-1', $composer->cve);
        $this->assertSame('2026-07-22 21:07:07', $composer->reportedAt);
        $this->assertSame('<6.4.1', $composer->affectedVersions);
        $this->assertTrue($composer->kevKnown);
        $this->assertTrue($composer->kev?->ransomware);

        $npm = ValtryAdvisorySource::advisory(Ecosystem::Npm, 'lodash', ['id' => 'GHSA-1', 'affected' => '<4.17.21', 'severity' => 'moderate', 'exploited' => false, 'kev' => null]);
        $this->assertNotNull($npm);
        $this->assertSame('GHSA-1', $npm->title);
        $this->assertNull($npm->kev);
        $this->assertTrue($npm->kevKnown);

        $this->assertNull(ValtryAdvisorySource::advisory(Ecosystem::Npm, 'x', ['id' => 'GHSA-2']), 'no range, no advisory');
    }

    public function testASecondScanIsServedFromTheCache(): void
    {
        $cache = new ArrayCache();
        $this->scanner(cache: $cache)->scan();
        $this->scanner(cache: $cache)->scan();

        $this->assertCount(2, $this->client->sentTo('valtry.test'));
    }

    public function testAnAnswerSlowerThanTheDeadlineIsNotUsed(): void
    {
        $client = MockClient::feeds();
        $valtry = new ValtryServer($client);
        $client->on('POST', 'valtry.test', function (RequestInterface $r) use ($valtry) {
            usleep(700_000);

            return $valtry->respond($r);
        });
        $factory = new Psr17Factory();
        $source = new ValtryAdvisorySource(new JsonClient($client, $factory, $factory), null, ValtryServer::URL, $valtry->keys(), deadline: 0.1);

        $this->expectException(\Ruvelo\SecurityAdvisories\Exceptions\SourceUnavailable::class);
        $this->expectExceptionMessage('took longer than 0.1 seconds');
        $source->advisories(Ecosystem::Npm, ['vite']);
    }

    public function testTheDeadlineIsPassedToAClientThatTakesOptions(): void
    {
        $client = new class () extends \Ruvelo\SecurityAdvisories\Tests\Support\RecordingOptionsClient {};
        $factory = new Psr17Factory();
        (new JsonClient($client, $factory, $factory))->withDeadline(5.0);

        $this->assertSame([['timeout' => 5.0, 'max_duration' => 5.0]], $client::$options);
    }
}
