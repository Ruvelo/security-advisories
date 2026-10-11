# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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
