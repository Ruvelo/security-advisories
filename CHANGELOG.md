# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned as 1.1.0. Backwards compatible: 1.0 adapters keep working unchanged.

### Added

- `Valtry\ValtryAdvisorySource`: Composer and npm advisories, with their CISA KEV verdict, from Valtry's Advisory API in one request per ecosystem. Sends package names only (never versions) and a random nonce; verifies every answer's Ed25519 signature against keys pinned in `Valtry\Keys`, the echoed nonce and that every name is covered. Times out after 5 seconds and leaves Valtry alone for five minutes after a failure.
- `Sources\FallbackAdvisorySource`: a primary source with fallbacks, per ecosystem. `Scanner::forProject()` now uses Valtry first and Packagist, OSV and CISA KEV directly when Valtry is unreachable, slow, answers with an error or a bad signature, or reports its data for that ecosystem as stale.
- Opting out: `Scanner::forProject(source: 'public')` or `RUVELO_ADVISORIES_SOURCE=public` (which wins) keeps every request off Valtry. `Scanner::source()` says which path applies.
- `Report::$source` (`valtry`, `public` or `mixed`) and `Report::$sources` per ecosystem, also in `toArray()`.
- `Reconciler::next()` takes keys to leave unacknowledged, so an alert that couldn't be delivered is news again on the next check.
- `Changes::$resolvedFindings` and `Changes::resolvedFinding()`: what a resolved finding was when last seen, from the new `Reconciler::lastSeen()` data passed to `reconcile()`. `Changes::$resolved` is unchanged.
- `Finding::fromArray()`, the reverse of `toArray()`.
- `Advisory::$kev` and `Advisory::$kevKnown`, for sources that know the KEV verdict themselves; the catalogue is then only downloaded for the rest.
- `JsonClient::postJsonRaw()` and `JsonClient::withDeadline()`, `ResponseCache::put()`.

### Security

- Fail-closed: while `Valtry\Keys` holds a placeholder, nothing is sent to Valtry, and CI refuses to build a release tag.

## [1.0.0] - 2026-10-12

First release: the logic of [Laravel Security Alerts](https://github.com/Ruvelo/laravel-security-alerts) and [Magento 2 Security Alerts](https://github.com/Ruvelo/magento2-security-alerts), without the framework.

### Added

- `Scanner`: reads package lists, asks the advisory sources about the installed versions, marks what CISA lists as exploited and returns a `Report`. Missing files and unreachable feeds become `Report::$problems` instead of exceptions. `Scanner::forProject()` wires up the usual setup for a project directory.
- Package sources behind `PackageSource`: `ComposerLockReader` (dev packages included and flagged), `NpmLockReader` (lockfile versions 1 to 3) and `ExtensionList` for inventories an adapter supplies (Joomla extensions, PrestaShop modules, Shopware plugins), with `Ecosystem::Extension`.
- Advisory sources behind `AdvisorySource`: `PackagistAdvisorySource` (package names only, batched) and `OsvSource` (npm, batch query plus advisory details). `KevCatalogue`, behind `ExploitCatalogue`, for CISA's Known Exploited Vulnerabilities.
- All HTTP through PSR-18 and PSR-17, found with `php-http/discovery` or passed in through `JsonClient`. An optional PSR-16 cache with `Ttls` defaulting to the Laravel package's lifetimes (advisories one hour, KEV six hours, OSV details one week).
- `Versions`: affected-version matching and fixed-in versions with `composer/semver`, following patch lines (`<2.4.4|>=2.4.4,<2.4.4-p9`) and ranges split by minor version, and falling back to `>X` when an advisory only names the last affected release.
- Immutable `Finding` with severity (including `Severity::NotRated`), fixed-in version, and the KEV entry (dates added and due, ransomware use) when exploited.
- `Report`: findings sorted exploited first, then by severity; `counts()`, `worst()`, `failing()`, `failsOn(Threshold)`, `isClean()`, `isComplete()` and `toArray()` / JSON.
- `Reconciler`: given the finding keys an adapter already knows, returns what is new, what became exploited and what is resolved, storing nothing. An incomplete report never resolves anything, and exploited never goes back to not exploited.
- Exceptions extending `SecurityAdvisoriesException`: `SourceUnavailable`, `PackagesUnreadable`, `InvalidThreshold`.

[Unreleased]: https://github.com/Ruvelo/security-advisories/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/Ruvelo/security-advisories/releases/tag/v1.0.0
