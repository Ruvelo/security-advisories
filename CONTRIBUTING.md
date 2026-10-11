# Contributing to Security Advisories

Thanks for helping! Wrong matches, docs fixes and features are all welcome.

## Before you start

- **A finding that's wrong, or one that's missing:** [open an issue](https://github.com/Ruvelo/security-advisories/issues/new) with the package, the installed version, and the advisory (its `PKSA-`, `GHSA-` or CVE ID). If the advisory itself is wrong, it's best fixed upstream, in the [GitHub Advisory Database](https://github.com/github/advisory-database) or [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories).
- **Features:** open an issue first if it's more than a small change. This library is the shared core of several platform modules, so its API changes slowly and on purpose.
- **Security issues:** don't open an issue. See [SECURITY.md](https://github.com/Ruvelo/.github/blob/main/SECURITY.md).

## What belongs here

Pure logic: reading package lists, talking to advisory feeds, matching versions, reports and reconciling. Storage, notifications, console commands and anything that needs a framework belong in the platform adapters, which depend on this library.

## Setup

You need PHP 8.2+ and Composer. Tests never touch the network.

```bash
git clone https://github.com/<you>/security-advisories && cd security-advisories
composer install
composer check
```

`composer check` runs exactly what CI runs:

| Command | What it does |
|---|---|
| `composer test` | PHPUnit |
| `composer lint` | Code style check (Pint, PSR-12) |
| `composer format` | Fix code style |
| `composer analyse` | Static analysis (PHPStan level 8) |

## The fixtures

`tests/fixtures` holds real answers from Packagist, OSV and CISA, recorded for the lockfiles of Halyard, a made-up app. `tests/Support/MockClient.php` is a PSR-18 client that serves them and records every request; a test that sends a request nobody expected fails.

- To test a new case, give the mock client its own answer (`$client->on('POST', 'packagist.org', $client->json([...]))`) rather than changing the shared fixtures.
- If you refresh the fixtures, record real responses, keep the KEV catalogue trimmed, and update the counts the tests expect.

## Making a change

1. Branch from `main`.
2. Write a test that fails without your change.
3. Keep the public API stable: the classes in `src/` that aren't marked `@internal`, the keys of `Finding::key()` and the shape of `toArray()`. Adapters store those. If you must change one, say so in the PR.
4. Run `composer format` and `composer check`.
5. Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).
6. Open the pull request.

## Where things live

```
src/Scanner.php               Package lists in, Report out
src/Packages/                 PackageSource, composer.lock and package-lock.json readers, ExtensionList
src/Sources/                  AdvisorySource, Packagist and OSV, ExploitCatalogue, CISA KEV
src/Http/JsonClient.php       PSR-18 / PSR-17 with discovery, retries
src/Cache/                    The optional PSR-16 cache and its lifetimes
src/Versions.php              Constraint matching and fixed versions
src/Report.php, Finding.php   What a scan returns
src/Reconciler.php            What's new, what became exploited, what's resolved
```

## Style

- `declare(strict_types=1)` everywhere, typed properties and return types, PSR-12 (Pint).
- No `@phpstan-ignore` or baseline entries: fix the cause.
- Comments explain *why*, not *what*.
- Target PHP 8.2: no features from later versions.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that you'll follow the [code of conduct](https://github.com/Ruvelo/.github/blob/main/CODE_OF_CONDUCT.md).
