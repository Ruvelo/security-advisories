<?php

declare(strict_types=1);

namespace Ruvelo\SecurityAdvisories\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Ruvelo\SecurityAdvisories\Ecosystem;
use Ruvelo\SecurityAdvisories\Exceptions\PackagesUnreadable;
use Ruvelo\SecurityAdvisories\Exceptions\SecurityAdvisoriesException;
use Ruvelo\SecurityAdvisories\InstalledPackage;
use Ruvelo\SecurityAdvisories\Packages\ComposerLockReader;
use Ruvelo\SecurityAdvisories\Packages\ExtensionList;
use Ruvelo\SecurityAdvisories\Packages\NpmLockReader;

class PackageSourcesTest extends TestCase
{
    private const FIXTURES = __DIR__.'/../fixtures';

    /**
     * @param list<InstalledPackage>|null $packages
     */
    private function find(?array $packages, string $name): ?InstalledPackage
    {
        foreach ($packages ?? [] as $package) {
            if ($package->name === $name) {
                return $package;
            }
        }

        return null;
    }

    public function testComposerLockWithDevPackagesFlagged(): void
    {
        $packages = (new ComposerLockReader(self::FIXTURES.'/composer.lock'))->packages();

        $this->assertCount(73, (array) $packages);
        $livewire = $this->find($packages, 'livewire/livewire');
        $this->assertSame('3.6.2', $livewire?->version, 'The v prefix is dropped');
        $this->assertSame(Ecosystem::Composer, $livewire->ecosystem);
        $this->assertFalse($livewire->isDev);
        $this->assertTrue($this->find($packages, 'phpunit/phpunit')?->isDev);
    }

    public function testComposerLockWithoutDevPackages(): void
    {
        $packages = (new ComposerLockReader(self::FIXTURES.'/composer.lock', includeDev: false))->packages();

        $this->assertCount(67, (array) $packages);
        $this->assertNull($this->find($packages, 'phpunit/phpunit'));
    }

    public function testNpmLockV3(): void
    {
        $packages = (new NpmLockReader(self::FIXTURES.'/package-lock.json'))->packages();

        $this->assertCount(38, (array) $packages);
        $this->assertSame(Ecosystem::Npm, ($packages[0] ?? null)?->ecosystem);
        $this->assertNotNull($this->find($packages, 'vite'));
    }

    public function testNpmLockV2KeepsScopedAndNestedNames(): void
    {
        $path = $this->write([
            'lockfileVersion' => 2,
            'packages' => [
                '' => ['name' => 'app', 'version' => '1.0.0'],
                'node_modules/@scope/pkg' => ['version' => '1.2.3'],
                'node_modules/a/node_modules/b' => ['version' => '2.0.0', 'dev' => true],
                'node_modules/b' => ['version' => '2.0.0'],
                'node_modules/linked' => ['link' => true, 'resolved' => 'packages/linked'],
                'packages/workspace' => ['version' => '0.0.1'],
            ],
        ]);

        $packages = (new NpmLockReader($path))->packages() ?? [];

        $this->assertSame(['@scope/pkg@1.2.3', 'b@2.0.0'], array_map(fn (InstalledPackage $p): string => $p->name.'@'.$p->version, $packages));
        $this->assertFalse($this->find($packages, 'b')?->isDev, 'A production copy wins over a dev copy');
        $this->assertCount(2, (new NpmLockReader($path, includeDev: false))->packages() ?? []);
    }

    public function testNpmLockV1(): void
    {
        $path = $this->write(['lockfileVersion' => 1, 'dependencies' => [
            'a' => ['version' => '1.0.0', 'dependencies' => ['b' => ['version' => '2.0.0', 'dev' => true]]],
            'local' => ['version' => 'file:../local'],
        ]]);

        $packages = (new NpmLockReader($path))->packages() ?? [];

        $this->assertSame(['a', 'b'], array_map(fn (InstalledPackage $p): string => $p->name, $packages));
        $this->assertTrue($this->find($packages, 'b')?->isDev);
        $this->assertCount(1, (new NpmLockReader($path, includeDev: false))->packages() ?? []);
    }

    public function testAMissingLockfileIsNull(): void
    {
        $this->assertNull((new ComposerLockReader('/nowhere/composer.lock'))->packages());
        $this->assertNull((new NpmLockReader('/nowhere/package-lock.json'))->packages());
        $this->assertTrue((new ComposerLockReader('/x'))->isRequired());
        $this->assertFalse((new NpmLockReader('/x'))->isRequired());
    }

    public function testABrokenLockfileIsATypedException(): void
    {
        try {
            (new ComposerLockReader($this->raw('{"packages": [')))->packages();
            $this->fail('No exception');
        } catch (PackagesUnreadable $e) {
            $this->assertInstanceOf(SecurityAdvisoriesException::class, $e);
            $this->assertStringContainsString('isn\'t valid JSON', $e->getMessage());
        }

        $this->expectException(PackagesUnreadable::class);
        $this->expectExceptionMessage('no "packages" list');
        (new ComposerLockReader($this->raw('{"content-hash": "x"}')))->packages();
    }

    public function testANpmLockWithNothingInItIsUnreadable(): void
    {
        $this->expectException(PackagesUnreadable::class);
        (new NpmLockReader($this->raw('{"name": "x"}')))->packages();
    }

    public function testAnInventoryFromTheAdapter(): void
    {
        $list = new ExtensionList(
            [
                ['name' => 'com_akeeba', 'version' => '9.1.0'],
                new InstalledPackage(Ecosystem::Extension, 'plg_system_x', '1.0.0', true),
            ],
            label: 'the Joomla extension list',
        );

        $packages = $list->packages();

        $this->assertSame(Ecosystem::Extension, $list->ecosystem());
        $this->assertSame('the Joomla extension list', $list->describe());
        $this->assertCount(2, $packages);
        $this->assertSame(Ecosystem::Extension, $packages[0]->ecosystem);
        $this->assertTrue($packages[1]->isDev);
    }

    /**
     * @param array<mixed> $data
     */
    private function write(array $data): string
    {
        return $this->raw((string) json_encode($data));
    }

    private function raw(string $contents): string
    {
        $path = tempnam(sys_get_temp_dir(), 'lock');
        $this->assertIsString($path);
        file_put_contents($path, $contents);
        $this->addToAssertionCount(0);
        register_shutdown_function(fn (): bool => @unlink($path));

        return $path;
    }
}
