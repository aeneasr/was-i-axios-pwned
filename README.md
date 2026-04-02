# was-i-axios-pwned

On March 31, 2026, malicious versions of the `axios` npm package (`1.14.1` and `0.30.4`) were briefly published to the npm registry. They installed a remote-access trojan via a companion package (`plain-crypto-js@4.2.1`). This tool performs **read-only forensic triage** of a host to determine whether it was exposed. It runs on macOS, Linux, and Windows.

## Quick start

**Requirements:** Go 1.21+

```bash
go install github.com/aeneasr/was-i-axios-pwned@latest
was-i-axios-pwned
```

Run a deep scan across the entire filesystem (recommended for thorough incident triage):

```bash
# Unix/macOS — sudo gives access to other users' home dirs and system paths
sudo was-i-axios-pwned --deep --report-dir ./report

# Windows PowerShell — run from an elevated prompt
was-i-axios-pwned --deep --report-dir .\report
```

See [Example output](#example-output) for what each verdict looks like.

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--deep` | `false` | Expand scanning to filesystem roots (`/` or Windows drives) and broader log coverage. Run with `sudo` (Unix) or an elevated prompt (Windows) for full coverage. |
| `--roots <paths>` | _(none)_ | Comma-separated list of additional project roots to scan beyond the defaults. |
| `--since <ISO8601>` | `2026-03-30T23:59:00Z` | Start time for log-based collectors. Filters npm logs and cache entries older than this timestamp. |
| `--report-dir <path>` | _(none)_ | Write a detailed report bundle to this directory (see [Report bundle](#report-bundle)). |

**Default scan roots** (without `--deep`): current working directory, user home directory, global npm root (`npm root -g`), npm cache and log directories, and fixed platform-specific IOC paths.

## Understanding the results

The output starts with a header block (verdict, coverage, platform, scan roots) followed by any findings, warnings, and next steps. The two key dimensions are **verdict** and **coverage**.

### Verdict

| Verdict | Meaning |
|---------|---------|
| `CONFIRMED` | Direct host evidence found: `node_modules/plain-crypto-js`, platform payload artifacts, live IOC process, or active C2 connection. |
| `LIKELY_EXPOSED` | Indirect evidence without a surviving host artifact: lockfile metadata, npm log entry, npm cache hit, or tarball hash match. |
| `NO_EVIDENCE` | No hits across all completed collectors. |

### Coverage

| Coverage | Meaning |
|----------|---------|
| `COMPLETE` | Every planned collector for this platform ran successfully. |
| `PARTIAL` | One or more collectors were skipped due to missing permissions or tooling. Consider re-running with `sudo` or `--deep`. |

### Range risk warning

`RANGE_RISK` is reported as a separate warning, not a verdict escalation. It means a declared `axios` version range in a manifest (e.g. `^1.14.0`) was permissive enough to have resolved to the malicious version during the publish window — but no direct install evidence was found on disk. Treat it as a review signal.

## Example output

**Clean host** — no evidence found, all collectors ran successfully:

```
Axios npm compromise triage
Verdict: NO_EVIDENCE
Coverage: COMPLETE
Platform: darwin
Since: 2026-03-30T23:59:00Z
Deep Scan: yes
Findings: 0
Warnings: 0
C2: sfrclak.com (142.11.206.73)
Roots:
  - /Users/dev
  - /Users/dev/projects/my-app
```

**Indirect evidence** — lockfile references a compromised version but no host artifacts survive:

```
Axios npm compromise triage
Verdict: LIKELY_EXPOSED
Coverage: COMPLETE
Platform: linux
Since: 2026-03-30T23:59:00Z
Deep Scan: yes
Findings: 2
Warnings: 0
C2: sfrclak.com (142.11.206.73)
Roots:
  - /home/deploy
  - /home/deploy/services/api

Findings
  - [LIKELY_EXPOSED] lockfile | axios@0.30.4 reference | /home/deploy/services/api/package-lock.json | Lockfile references a compromised axios version. resolved=... integrity=...
  - [LIKELY_EXPOSED] npm_cache | cache metadata IOC | /home/deploy/.npm/_cacache/index-v5 | npm cache metadata references a malicious tarball URL.

Immediate Next Steps
  - Treat this host as compromised until proven otherwise.
  - Isolate the machine, rotate secrets from a clean system, and rebuild from known-good media.
  - Review installs and logs around 2026-03-31 00:21:00Z through 2026-03-31 03:15:30Z.
```

**Host compromise confirmed** — malicious package installed and payload artifact present:

```
Axios npm compromise triage
Verdict: CONFIRMED
Coverage: PARTIAL
Platform: darwin
Since: 2026-03-30T23:59:00Z
Deep Scan: no
Findings: 3
Warnings: 1
C2: sfrclak.com (142.11.206.73)
Roots:
  - /Users/dev
  - /Users/dev/projects/my-app

Findings
  - [CONFIRMED] package_directory | plain-crypto-js | /Users/dev/projects/my-app/node_modules/plain-crypto-js | Found plain-crypto-js under node_modules. This dependency only appeared in the malicious axios releases.
  - [CONFIRMED] manifest_hook | postinstall node setup.js | /Users/dev/projects/my-app/node_modules/plain-crypto-js/package.json | package.json still contains the malicious postinstall hook.
  - [CONFIRMED] artifact | /Library/Caches/com.apple.act.mond | /Library/Caches/com.apple.act.mond | Found the documented macOS second-stage artifact path.

Warnings
  - [COVERAGE] macOS unified log access was denied. Re-run with elevated privileges for fuller coverage.

Immediate Next Steps
  - Treat this host as compromised until proven otherwise.
  - Isolate the machine, rotate secrets from a clean system, and rebuild from known-good media.
  - Review installs and logs around 2026-03-31 00:21:00Z through 2026-03-31 03:15:30Z.
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | `NO_EVIDENCE` + `COMPLETE`, or only `RANGE_RISK` warnings |
| `1` | `LIKELY_EXPOSED` or `PARTIAL` coverage |
| `2` | `CONFIRMED` |
| `3` | Fatal scanner failure (I/O error, bad config, etc.) |

## What to do if you get a hit

A `CONFIRMED` or `LIKELY_EXPOSED` result should be treated as an **incident response trigger**, not as a cleanup recommendation. Specifically:

- **Preserve evidence** before doing anything else — do not reinstall packages, clear caches, or run `npm install`.
- **Rotate credentials** that were accessible to the process environment on the affected host.
- **Isolate the host** from the network if active C2 connections or IOC processes were found (`CONFIRMED`).
- Refer to the sources below for full remediation guidance.

The scanner is **read-only** — it does not quarantine, delete, or modify anything on the host.

## Report bundle

When `--report-dir` is specified, the scanner writes the following files:

| File | Contents |
|------|----------|
| `summary.txt` | Human-readable summary identical to the console output |
| `findings.tsv` | Tab-separated findings: Severity, Source, Indicator, Location, Detail |
| `warnings.txt` | Tab-separated warnings, class-prefixed (e.g. `COVERAGE`, `RANGE_RISK`) |
| `raw/*.txt` | Raw evidence snippets: process listings, network connections, log matches |

The TSV files are suitable for ingestion into SIEM tools or spreadsheets.

## IOC reference

The scanner checks for all indicators documented in the linked public analyses.

**Malicious package versions:**
- `axios@1.14.1`, `axios@0.30.4`
- `plain-crypto-js@4.2.1` (including the post-cleanup fake `4.2.0` manifest state)

**Published hashes:**

| Package | Algorithm | Hash |
|---------|-----------|------|
| `axios@1.14.1` | SHA-1 | `2553649f2322049666871cea80a5d0d6adc700ca` |
| `axios@0.30.4` | SHA-1 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` |
| `plain-crypto-js@4.2.1` | SHA-1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` |
| `setup.js` | SHA-256 | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` |

**C2 infrastructure:**
- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- Full URL: `http://sfrclak.com:8000/6202033`

**Data exfiltration POST markers:**
- `packages.npm.org/product0`, `packages.npm.org/product1`, `packages.npm.org/product2`

**Platform-specific payload artifacts:**

| Platform | Path |
|----------|------|
| macOS | `/Library/Caches/com.apple.act.mond`, `/tmp/6202033` |
| Linux | `/tmp/ld.py` |
| Windows | `%ProgramData%\wt.exe`, `%TEMP%\6202033.ps1`, `%TEMP%\6202033.vbs` |

## Development

Run the tests:

```bash
go test ./...
```

Validate the release build locally:

```bash
go build .
go run . --help
goreleaser check
goreleaser release --snapshot --clean
```

The test suite covers:

- Manifest and lockfile detection
- Hidden `node_modules/.package-lock.json` evidence
- `plain-crypto-js` anti-forensics residue
- Deterministic `go run .` end-to-end fixture coverage
- Windows artifact detection
- Semver range warnings and exit-code behavior

## Sources

- Penligent: <https://www.penligent.ai/hackinglabs/axios-compromised-on-npm-what-the-malicious-releases-actually-did/>
- StepSecurity: <https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan>
