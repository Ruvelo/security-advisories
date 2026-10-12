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

- `Report::$unchecked` (`UncheckedPackage`: the `InstalledPackage` and a reason): packages no advisory source covers (zip-installed plugins, say). They are an inventory, not a problem, so they no longer make `isComplete()` false. This replaces the "No advisory source covers ..." problem 1.0 added for them.
- `Report::$notes` (`Note`: message, package, ecosystem, link) and `Report::hasNotes()`: non-fatal remarks such as "advisory found but affected versions unreadable, check by hand". Notes never block resolving. A source emits them by also implementing the optional `Sources\EmitsNotes`; sources that don't need no change. `FallbackAdvisorySource` passes the notes of whoever answered through.
- `Scanner::forProject()` options: `ecosystems: [Ecosystem::Composer]` to read and ask about only some of Composer and npm, `extraSources` and `extraPackageSources` to add an adapter's own feeds and inventories, and `exploits` for another exploited-vulnerability catalogue.
- Stored form: `Finding::toArray()` carries a shape version (`v`, `Finding::SHAPE`), `aliases`, `links` and `meta`; `Report::fromArray()` rebuilds a report (findings, unchecked packages, notes). Both read what 1.0 stored. `Report::toArray()` gains `unchecked`, `notes` and `v`.
- Cross-source dedupe in the Scanner: the same vulnerability from two sources (same id, same CVE, or overlapping aliases, on the same package) is one finding. The match with exact ranges wins, then the one that names a fix; aliases and links are merged, and an exploited verdict from either is kept. `Sources\MatchMerger` is the implementation. `Advisory` gains `$aliases`, `$links` and `hasExactRanges()`; the catalogue is also asked about CVEs that only appear as aliases.
- `JsonClient::getText()` for feeds that aren't JSON (markdown advisories), and `ResponseCache::rememberText()`, `getText()` and `putText()` so they can be cached (kept apart from the array entries).
- `Http\CurlClient`: a small PSR-18 client on ext-curl, for platforms where discovery finds no client or a conflicting one. Verifies TLS, follows a few http(s) redirects, applies timeouts, throws `Http\CurlException` (a PSR-18 `NetworkExceptionInterface`) and takes an injectable transport.
- `Cache\FileCache`: a PSR-16 cache in a directory for platforms without one. Hashed file names, atomic writes (temporary file, then rename), TTLs, an owner-only directory, and values read back without instantiating classes.
- `InstalledPackage::$metadata` (`array<string, scalar>`, e.g. `active: false`, `source: 'zip'`), also accepted as `metadata` by `ExtensionList`, and passed through to `Finding::$metadata`.
- `Finding::$aliases`, `$links` and `$metadata` (constructor arguments added at the end).

- Stable finding identity: `Finding::altKeys()` (`ecosystem:package:<x>` for the id, CVE and every alias). The Reconciler counts a finding as known when its `key()` or any alt key is in the known set, carries the exploited state over the same way, and resolves only entries no current finding matches. `next()` keeps the key a finding was first stored under, so a different winning source or dedupe result is neither new nor resolved and no alert is re-sent. `key()` and 1.0 stored keys are unchanged. Pass `lastSeen()` data (new optional argument of `next()`, as `reconcile()` already took) so a stored entry is also recognised by the CVE and aliases it had.

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
