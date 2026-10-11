<p align="center">
  <a href="https://github.com/Ruvelo/security-advisories/actions/workflows/tests.yml"><img src="https://github.com/Ruvelo/security-advisories/actions/workflows/tests.yml/badge.svg" alt="Tests"></a>
  <img src="https://img.shields.io/badge/PHP-8.2%2B-3d4eff" alt="PHP 8.2+">
  <img src="https://img.shields.io/badge/PHPStan-level%208-3d4eff" alt="PHPStan level 8">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3d4eff" alt="MIT license"></a>
</p>

# Security Advisories

**The core behind Ruvelo's security alerts for Laravel, Symfony, Shopware, PrestaShop, Joomla and more.** It reads a project's lockfiles, asks Packagist and OSV which installed versions are vulnerable, marks what CISA says attackers are exploiting, and works out what changed since last time. No framework, no storage, no notifications: those belong to the platform modules built on it, so a fix here reaches all of them.

```
composer require ruvelo/security-advisories
```

You also need a PSR-18 client and PSR-17 factories. If your app has Symfony HttpClient or Guzzle, you have one; otherwise `composer require symfony/http-client nyholm/psr7`.

## Usage

```php
use Ruvelo\SecurityAdvisories\{Reconciler, Scanner, Threshold};

$scanner = Scanner::forProject('/srv/app', cache: $psr16Cache);   // composer.lock, package-lock.json, CISA KEV
$report  = $scanner->scan();

foreach ($report->findings as $finding) {                         // exploited first, then by severity
    echo "{$finding->package} {$finding->installed}: {$finding->title}"
        .($finding->isExploited() ? ' (EXPLOITED)' : '')
        .($finding->fixedIn ? " -> {$finding->fixedIn}" : '')."\n";
}

if (! $report->isComplete()) {
    print_r($report->problems);                                   // "no findings" is not "clean" when this isn't empty
}

$changes = (new Reconciler())->reconcile($knownFromYourStorage, $report);   // array<string, bool>: key => was exploited
$changes->new;        // list<Finding>
$changes->exploited;  // list<Finding> that just became exploited
$changes->resolved;   // list<string> keys that are gone

$knownFromYourStorage = (new Reconciler())->next($knownFromYourStorage, $report);   // store this for next time
exit($report->failsOn(Threshold::High) ? 1 : 0);
```

`Scanner::forProject()` takes a `JsonClient` if you want to pass your own PSR-18 client and factories (`new JsonClient($client, $requestFactory, $streamFactory)`); without one, `php-http/discovery` finds them.

## What it gives you

| Class | What it is |
|---|---|
| `Scanner` | `scan(bool $fresh = false): Report`. Never throws for a missing file or a failing feed. |
| `Report` | Immutable. `findings` (worst first), `counts()`, `worst()`, `exploited()`, `failing($t)`, `failsOn($t)`, `isClean()`, `isComplete()`, `problems`, `toArray()` / JSON. |
| `Finding` | Immutable. Package, installed version, advisory id, title, link, CVE, `Severity` (including `NotRated`), `fixedIn`, `exploited` (a `KevEntry` with dates added and due, and ransomware use), `isDev`, and a stable `key()`. |
| `Reconciler` | `reconcile($known, $report): Changes` and `next($known, $report)`. Stores nothing. An incomplete report never resolves anything. |
| `Versions` | `affects()` and `fixedIn()` on `composer/semver`. Follows patch lines and minor-split ranges; says `>2.10.1` when an advisory only names the last affected release. |

## Where it looks, and what it sends

| Source | Used for | What leaves your server |
|---|---|---|
| [Packagist](https://packagist.org/apidoc#list-security-advisories) | Composer packages | **Package names only.** Versions are matched locally. |
| [OSV.dev](https://osv.dev) | npm packages | **Names and exact versions** of npm packages, then advisory ids. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Exploited in the wild | Nothing: the whole catalogue is downloaded. |

Everything goes through the PSR-18 client you give it, and is cached with PSR-16 if you pass a cache (advisories one hour, KEV six hours, OSV details one week; change them with `Ttls`). No keys, no accounts, no other requests.

## Extension points

- **Another HTTP client:** any PSR-18 client with PSR-17 factories, through `JsonClient`. Timeouts and redirects are the client's settings.
- **Another cache:** any PSR-16 cache, through `Scanner::forProject(cache: ...)` or `ResponseCache` for the individual sources.
- **Extension inventories:** implement `PackageSource`, or pass a list to `ExtensionList` (Joomla extensions, PrestaShop modules, Shopware plugins). Packages that are also Composer packages use `Ecosystem::Composer` and Packagist covers them.
- **Another advisory feed:** implement `AdvisorySource` (`supports()` and `find()`) and give it to `new Scanner($packageSources, $advisorySources, $exploits)`. Throw `SourceUnavailable` when the feed can't be read in full, and the report says so instead of looking clean.
- **Another exploited list:** implement `ExploitCatalogue`.

```php
$scanner = new Scanner(
    [new ComposerLockReader($dir.'/composer.lock', includeDev: false), new ExtensionList($joomlaExtensions)],
    [new PackagistAdvisorySource(), new YourJoomlaAdvisories()],
    new KevCatalogue(),
);
```

## Development

`composer check` runs code style (Pint, PSR-12), static analysis (PHPStan level 8) and the tests, exactly as CI does. The tests never touch the network: a mock PSR-18 client serves real recorded responses from `tests/fixtures`. See [CONTRIBUTING.md](CONTRIBUTING.md) and the [changelog](CHANGELOG.md).

## Credits

Built by [François Bultez](https://github.com/francoisbultez) at [Valtry](https://valtry.co.uk/?utm_source=ruvelo&utm_medium=github&utm_campaign=security-advisories), the website security scanner, and everyone who [contributes](https://github.com/Ruvelo/security-advisories/graphs/contributors).

Advisories come from [Packagist](https://packagist.org) (and through it the [GitHub Advisory Database](https://github.com/advisories) and [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories)), [OSV.dev](https://osv.dev) and [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Thanks to everyone who maintains them.

## License

MIT. See [LICENSE](LICENSE).
