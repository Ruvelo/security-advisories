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

$reconciler = new Reconciler();
$changes = $reconciler->reconcile($known, $report, $lastSeen);   // $known: key => was exploited; $lastSeen: optional, see below
$changes->new;               // list<Finding>
$changes->exploited;         // list<Finding> that just became exploited
$changes->resolved;          // list<string> keys that are gone
$changes->resolvedFindings;  // key => Finding as last seen, for the keys you kept data for

$failed = [/* keys whose alert couldn't be delivered */];
$known    = $reconciler->next($known, $report, $failed);         // store this for next time; $failed stay news
$lastSeen = $reconciler->lastSeen($lastSeen, $report, $known);   // and this, to say more than a key when one resolves
exit($report->failsOn(Threshold::High) ? 1 : 0);
```

`Scanner::forProject()` takes a `JsonClient` if you want to pass your own PSR-18 client and factories (`new JsonClient($client, $requestFactory, $streamFactory)`); without one, `php-http/discovery` finds them.

## What it gives you

| Class | What it is |
|---|---|
| `Scanner` | `scan(bool $fresh = false): Report`. Never throws for a missing file or a failing feed. |
| `Report` | Immutable. `findings` (worst first), `counts()`, `worst()`, `exploited()`, `failing($t)`, `failsOn($t)`, `isClean()`, `isComplete()`, `problems`, `source` (`valtry`, `public` or `mixed`) and `sources` per ecosystem, `toArray()` / JSON. |
| `Finding` | Immutable. Package, installed version, advisory id, title, link, CVE, `Severity` (including `NotRated`), `fixedIn`, `exploited` (a `KevEntry` with dates added and due, and ransomware use), `isDev`, and a stable `key()`. |
| `Reconciler` | `reconcile($known, $report, $lastSeen = []): Changes`, `next($known, $report, $unacknowledged = [])` and `lastSeen()`. Stores nothing. An incomplete report never resolves anything; unacknowledged keys stay news until delivered. |
| `Versions` | `affects()` and `fixedIn()` on `composer/semver`. Follows patch lines and minor-split ranges; says `>2.10.1` when an advisory only names the last affected release. |

## Data sources

By default a scan asks **Valtry first** and the **public feeds** whenever Valtry can't answer. Both paths give the same findings: Valtry serves the same Packagist, OSV and CISA KEV data, normalised, from one request per ecosystem.

| Path | Used for | What leaves your server |
|---|---|---|
| [Valtry Advisory API](https://valtry.co.uk/docs/api/advisories) (default) | Composer and npm packages, and whether each advisory is exploited (CISA KEV) | **Package names only**, and a random nonce. Never versions: they are matched locally with `composer/semver`. |
| [Packagist](https://packagist.org/apidoc#list-security-advisories) (fallback, or opted out) | Composer packages | **Package names only.** Versions are matched locally. |
| [OSV.dev](https://osv.dev) (fallback, or opted out) | npm packages | **Names and exact versions** of npm packages, then advisory ids. |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (fallback, or opted out) | Exploited in the wild | Nothing: the whole catalogue is downloaded. |

Valtry doesn't log or store the names it is sent, or pair them with your address. Its privacy terms are on [the API page](https://valtry.co.uk/docs/api/advisories).

**Signed answers.** Every Valtry answer carries an Ed25519 signature (`X-Valtry-Signature: ed25519=…; kid=…`) over its exact body. The library verifies it against public keys pinned in `src/Valtry/Keys.php`, never against a key it downloads, and checks that the answer echoes the request's nonce and covers every name asked about. A hijacked DNS record, a TLS-intercepting proxy or a replayed old answer fails those checks. Verification needs `ext-sodium`, which PHP bundles.

**Fallback.** For each ecosystem, the public feeds answer instead when Valtry:

- can't be reached, or takes longer than 5 seconds;
- answers with an error (any status but 200, including 429 and 5xx);
- sends an answer that doesn't verify: a bad or missing signature, an unknown key, another request's nonce, or missing packages;
- says its own data for that ecosystem is stale (a feed behind it missed its sync window).

After a network failure, an error or a bad signature, Valtry is left alone for five minutes (in your PSR-16 cache, if you pass one). `$report->source` says which path answered (`valtry`, `public`, or `mixed` when they differed), and `$report->sources` has it per ecosystem. An ecosystem never gets half an answer from each.

The 5 seconds are enforced by the HTTP client: without a client of your own, the library builds one with that timeout from Symfony HttpClient or Guzzle when either is installed; a Symfony `Psr18Client` you pass gets a copy with the timeout. With another client, give it a short timeout yourself: an answer that arrives late is still discarded, but only after it arrives.

**Fail-closed until a key is pinned.** While `Keys::PINNED` holds a placeholder, the Valtry path sends nothing and every scan uses the public feeds. CI refuses to build a tag with a placeholder left. To pin the key, run `php artisan advisories:keygen` on Valtry, paste the printed `'kid' => 'base64',` line into `Keys::PINNED`, release, and only then switch Valtry to the new key. To rotate keys, add the new kid beside the old one, release, switch Valtry, and drop the old kid a release later.

**Opting out.** To never contact Valtry, pass `source: 'public'`:

```php
$scanner = Scanner::forProject('/srv/app', cache: $psr16Cache, source: 'public');
```

or set `RUVELO_ADVISORIES_SOURCE=public` in the environment. The environment variable wins over code, so a server's owner can opt out without touching an adapter's configuration.

Everything goes through the PSR-18 client you give it, and is cached with PSR-16 if you pass a cache (advisories one hour, KEV six hours, OSV details one week; change them with `Ttls`). No keys, no accounts, no other requests.

## Extension points

- **Another HTTP client:** any PSR-18 client with PSR-17 factories, through `JsonClient`. Timeouts and redirects are the client's settings (see the 5 seconds above for Valtry).
- **Another primary source:** `FallbackAdvisorySource` takes any `AdvisorySource` first and a list of fallbacks, and reports which answered through `ReportsOrigin`.
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

Advisories come from [Valtry](https://valtry.co.uk/docs/api/advisories), [Packagist](https://packagist.org) (and through it the [GitHub Advisory Database](https://github.com/advisories) and [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories)), [OSV.dev](https://osv.dev) and [CISA](https://www.cisa.gov/known-exploited-vulnerabilities-catalog). Thanks to everyone who maintains them.

## License

MIT. See [LICENSE](LICENSE).
