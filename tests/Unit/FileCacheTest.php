<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use DateInterval;
use PHPUnit\Framework\TestCase;
use Psr\SimpleCache\CacheInterface;
use Ruvelo\SecurityAdvisories\Cache\FileCache;
use Ruvelo\SecurityAdvisories\Cache\InvalidKey;
use Ruvelo\SecurityAdvisories\Cache\ResponseCache;
use Ruvelo\SecurityAdvisories\Cache\Ttls;

class FileCacheTest extends TestCase
{
    private string $dir;

    private int $now = 1_000_000;

    protected function setUp(): void
    {
        $this->dir = sys_get_temp_dir().'/ruvelo-filecache-'.bin2hex(random_bytes(6));
    }

    protected function tearDown(): void
    {
        foreach (glob($this->dir.'/{*,.[!.]*}', GLOB_BRACE) ?: [] as $file) {
            @unlink($file);
        }
        @rmdir($this->dir);
    }

    private function cache(): FileCache
    {
        return new FileCache($this->dir, fn (): int => $this->now);
    }

    public function testItStoresAndReadsAnyKindOfValue(): void
    {
        $cache = $this->cache();

        $this->assertInstanceOf(CacheInterface::class, $cache);
        $this->assertTrue($cache->set('array', ['a' => [1, 2], 'b' => null], 60));
        $this->assertTrue($cache->set('text', "# markdown\n", 60));
        $this->assertTrue($cache->set('false', false, 60));

        $this->assertSame(['a' => [1, 2], 'b' => null], $cache->get('array'));
        $this->assertSame("# markdown\n", $cache->get('text'));
        $this->assertFalse($cache->get('false', 'default'), 'a stored false is not a miss');
        $this->assertSame('default', $cache->get('missing', 'default'));
        $this->assertTrue($cache->has('text'));
        $this->assertFalse($cache->has('missing'));
    }

    public function testEntriesExpireAfterTheirTtl(): void
    {
        $cache = $this->cache();
        $cache->set('short', 'x', 60);
        $cache->set('long', 'y', 3600);
        $cache->set('forever', 'z');

        $this->now += 59;
        $this->assertSame('x', $cache->get('short'));

        $this->now += 1;
        $this->assertNull($cache->get('short'), 'expired at the second the ttl ends');
        $this->assertFalse($cache->has('short'));
        $this->assertSame('y', $cache->get('long'));

        $this->now += 10_000_000;
        $this->assertNull($cache->get('long'));
        $this->assertSame('z', $cache->get('forever'), 'no ttl never expires');
        $this->assertCount(1, glob($this->dir.'/*.cache') ?: [], 'expired files are removed when met');
    }

    public function testADateIntervalIsATtl(): void
    {
        $cache = $this->cache();
        $cache->set('k', 'v', new DateInterval('PT2M'));

        $this->now += 119;
        $this->assertSame('v', $cache->get('k'));
        $this->now += 1;
        $this->assertNull($cache->get('k'));
    }

    public function testAZeroOrNegativeTtlStoresNothingAndDropsTheOldValue(): void
    {
        $cache = $this->cache();
        $cache->set('k', 'old', 60);

        $this->assertTrue($cache->set('k', 'new', 0));
        $this->assertNull($cache->get('k'));
        $this->assertTrue($cache->set('k2', 'new', -5));
        $this->assertFalse($cache->has('k2'));
    }

    public function testKeysBecomeSafeFileNames(): void
    {
        $cache = $this->cache();
        $keys = ['../../etc/passwd', 'a/b\\c', 'ruvelo.security-advisories.packagist:acme/lib', "line\nbreak", str_repeat('k', 5000), 'ünïcode', 'CON'];

        foreach ($keys as $i => $key) {
            $this->assertTrue($cache->set($key, $i, 60));
        }
        foreach ($keys as $i => $key) {
            $this->assertSame($i, $cache->get($key));
        }

        $files = glob($this->dir.'/*') ?: [];
        $this->assertCount(count($keys), $files);
        foreach ($files as $file) {
            $this->assertMatchesRegularExpression('/^[0-9a-f]{64}\.cache$/', basename($file));
        }
        $this->assertFileDoesNotExist(dirname($this->dir).'/etc/passwd');
    }

    public function testAnEmptyKeyIsRejected(): void
    {
        $this->expectException(InvalidKey::class);

        $this->cache()->get('');
    }

    public function testWritesAreAtomicAndLeaveNoTemporaryFiles(): void
    {
        $cache = $this->cache();
        $cache->set('k', str_repeat('a', 100_000), 60);
        $cache->set('k', str_repeat('b', 100_000), 60);

        $this->assertSame(str_repeat('b', 100_000), $cache->get('k'));
        $this->assertSame([], glob($this->dir.'/.tmp*') ?: [], 'no temporary files left');
        $this->assertCount(1, glob($this->dir.'/*') ?: []);
    }

    public function testAReaderNeverSeesAPartialWrite(): void
    {
        // A truncated or corrupt file (a crash mid-write on a filesystem without atomic rename) is a miss, not an error.
        $cache = $this->cache();
        $cache->set('k', ['big' => str_repeat('x', 1000)], 60);
        $file = (glob($this->dir.'/*.cache') ?: [])[0];
        file_put_contents($file, substr((string) file_get_contents($file), 0, 40));

        $this->assertNull($cache->get('k'));
        $this->assertFileDoesNotExist($file);
    }

    public function testObjectsAreNeverInstantiatedOnRead(): void
    {
        $cache = $this->cache();
        $cache->set('k', 1, 60);
        $file = (glob($this->dir.'/*.cache') ?: [])[0];
        file_put_contents($file, serialize([null, new \ArrayObject([1])]));

        $value = $cache->get('k');

        $this->assertNotInstanceOf(\ArrayObject::class, $value);
    }

    public function testDeleteClearAndMultiple(): void
    {
        $cache = $this->cache();

        $this->assertTrue($cache->setMultiple(['a' => 1, 'b' => 2, 'c' => 3], 60));
        $this->assertSame(['a' => 1, 'b' => 2, 'x' => null], iterator_to_array($cache->getMultiple(['a', 'b', 'x'])));
        $this->assertTrue($cache->delete('a'));
        $this->assertTrue($cache->delete('never-existed'));
        $this->assertTrue($cache->deleteMultiple(['b']));
        $this->assertSame(['c'], array_keys(array_filter(['a' => $cache->has('a'), 'b' => $cache->has('b'), 'c' => $cache->has('c')])));

        file_put_contents($this->dir.'/keep.txt', 'not ours');
        $this->assertTrue($cache->clear());
        $this->assertFalse($cache->has('c'));
        $this->assertFileExists($this->dir.'/keep.txt', 'only cache files are cleared');
        unlink($this->dir.'/keep.txt');
    }

    public function testItCreatesItsDirectoryPrivately(): void
    {
        $this->cache()->set('k', 'v', 60);

        $this->assertDirectoryExists($this->dir);
        $this->assertSame('0700', substr(sprintf('%o', fileperms($this->dir)), -4));
    }

    public function testAnUnwritableDirectoryFailsQuietly(): void
    {
        $cache = new FileCache('/proc/definitely/not/writable', fn (): int => $this->now);

        $this->assertFalse($cache->set('k', 'v', 60));
        $this->assertNull($cache->get('k'));
    }

    public function testItBacksTheResponseCacheForArraysAndText(): void
    {
        $responses = new ResponseCache($this->cache(), new Ttls());
        $fetches = 0;

        $first = $responses->rememberText('md', 60, false, function () use (&$fetches): string {
            $fetches++;

            return '# Advisory';
        });
        $second = $responses->rememberText('md', 60, false, function () use (&$fetches): string {
            $fetches++;

            return 'changed';
        });
        $fresh = $responses->rememberText('md', 60, true, fn (): string => 'refreshed');

        $this->assertSame(['# Advisory', '# Advisory', 'refreshed'], [$first, $second, $fresh]);
        $this->assertSame(1, $fetches);
        $this->assertSame('refreshed', $responses->getText('md', 60));
    }
}
