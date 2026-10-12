# Canary Killer technical guide

[Back to the README](../README.md#canary-killer-optional-repository-scan) | [Observed validation results](validation/canary-killer/README.md)

Canary Killer is the optional repository scan for project scripts, configured Git hooks and residual files under explicit local roots. It complements the dependency audit by inspecting files already present on disk, including missing-target references and separately supplied temporary directories. Scans are read-only by default. Optional protection removes confirmed direct canary calls, quarantines exact `canary.js` files and adds Git ignore rules.

## Architecture

The command is registered through the existing command loader. Its separate repository orchestrator keeps coverage reporting and indicator/review findings distinct from the dependency audit's package scores and vulnerability verdicts.

| Component | Role |
| --- | --- |
| [Command](../src/commands/canary-killer.js) and [repository scanner](../src/core/repositoryScanner.js) | Parse explicit roots/exclusions; traverse local files; report findings, references and coverage gaps |
| [Command parser](../src/utils/command.js) and [import extraction](../src/core/requireWalker.js) | Reuse existing static target parsing without executing targets |
| Existing network, environment and filesystem [marshallers](../src/marshallers/) | Supply shared detection signals alongside repository-specific behavior patterns |
| [Output helpers](../src/utils/output.js) | Reuse terminal formatting; emit repository-specific JSON/text reports |
| [Quarantine helper](../src/core/canaryQuarantine.js) | On explicit `--quarantine`, move discovered `canary.js` files and append ignore rules; preserve the file contents and report each action |
| [Reference repair](../src/core/canaryRepair.js) and [protection gate](../src/core/canaryProtection.js) | Remove confirmed direct calls, preserve remaining commands, and block controlled commands when protection fails |

The standalone repository commands read trusted-file settings but bypass dependency audit settings, registry/vulnerability requests and update checks. The dependency audit retains its existing behavior unless canary protection is enabled; enabled protection runs before auditing and again immediately before controlled npm launches. Protected npm launches also automatically inherit the Node startup guard.

## Run from a checkout

Node.js 18 or newer and a local checkout containing this implementation are required. From the np-audit checkout directory, run the CLI file directly; no global np-audit install, npm alias or package download is required:

```bash
node bin/npa.js canary-killer . --json
```

Here, `.` explicitly selects the np-audit checkout as the scan root. To inspect another repository or directories on the machine where Node is running, use the CLI's actual checkout path:

```bash
node /path/to/np-audit/bin/npa.js canary-killer /path/to/checkout --json
node /path/to/np-audit/bin/npa.js canary-killer /srv/app /dev/shm /tmp
node /path/to/np-audit/bin/npa.js canary-killer ./checkout --exclude ./checkout/node_modules
```

## Opt-in quarantine

From the np-audit checkout, scan selected directory roots and quarantine discovered `canary.js` files:

```bash
node bin/npa.js canary-killer /path/to/repository --quarantine --json
node bin/npa.js canary-killer /srv/app /dev/shm --quarantine --json
```

This option removes confirmed direct canary calls from package scripts and hooks, moves regular `canary.js` files into `.np-audit-quarantine/`, and appends `canary.js` plus `.np-audit-quarantine/` to `.gitignore`. It applies by filename, including legitimate canary tests, except for exact trusted path/hash matches. Quarantine is not a malware verdict. Explicit exclusions remain respected. Single-file roots remain available for read-only scanning; quarantine requires directory roots.

Each file is moved into a separate entry directory as `payload.quarantined`. A `metadata.json` records its original path, quarantine path, size, original permission mode and action time. File contents are preserved. The helper uses the nearest discovered Git repository root within the supplied roots, or the most specific supplied directory root when no repository is discovered. Quarantine storage and `.gitignore` writes stay inside supplied roots, and symlinks/reparse points are refused. Existing ignore content is preserved; repeated actions do not duplicate the appended block. Git index and history remain unchanged, so ignore rules do not remove already tracked content or prevent forced staging.

The JSON `repairs` and `quarantine.actions` lists and text output report original command text, replacements, paths, destinations, ignore updates and failures. The report retains pre-action evidence and coverage gaps, then rescans to report the current state. Quarantine storage is explicitly excluded from analysis and reported. Successful protection can still return exit code `2` from the standalone scan for incomplete overall coverage; `protection.allowed` reports whether the narrower canary protection checks succeeded.

For `"build": "node canary.js && tsc"`, repair preserves `"build": "tsc"`. A prepare entry containing only `node canary.js` is removed. Confirmed direct hook calls receive the same treatment. Repair also handles these references when the file is already missing. Only recognizable direct commands and simple `&&` chains are rewritten. Ambiguous conditions, pipelines or other unsupported canary calls are reported and block protection instead of being guessed. No scanned command is executed during protection.

## Automatic protection before controlled commands

To enable protection for a project, add these settings to its `.npmauditor.json`, preserving any existing settings:

```json
{
  "canaryProtection": true,
  "canaryRoots": []
}
```

The current project directory is always included. `canaryRoots` adds explicitly selected directories, such as `/dev/shm`; relative entries resolve from the command's working directory. Enabled protection runs for `scan`, `install`, `ci` and npm commands forwarded through np-audit. `--skip` and `--review` do not bypass it. For one command without changing configuration, run from the project directory:

```bash
node /path/to/np-audit/bin/npa.js run build --protect-canary
```

Protection discovers filenames throughout selected roots and reads manifests, hooks, Git configuration and `canary.js` contents. Other files are counted as filename-only coverage; use the standalone read-only scan for behavior matching in renamed files. Unreadable paths, discovery limits, unsupported hook configuration, failed actions and remaining canary references block the controlled command. Expected Git object/index and quarantine-storage exclusions remain reported but do not alone block this specific protection policy. Global npm operations and commands selecting another project with `--prefix` or `-C` are refused while protection is enabled.

In plain English: np-audit checks and repairs the selected folders before starting commands it launches. If protection fails, it stops the command. Its protected npm launches and inherited Node children also check at Node startup. Direct Node commands can receive this check through the session settings below. Unconfigured commands and non-Node programs remain outside that startup guard. Protection cannot undo code that already ran or stop an already running process. The optional monitor checks for files introduced later while it is running; it does not intercept execution. Quarantine is a filesystem move, not an isolated execution environment; use stable files while applying actions.

## Preserve intentional canaries

Add explicit trusted files to `.npmauditor.json`, preserving existing settings:

```json
{
  "canaryTrustedFiles": [
    {"path": "tests/canary.js", "sha256": "REPLACE_WITH_THE_FILES_64_CHARACTER_SHA256"}
  ]
}
```

Read the file's SHA-256 without executing it:

```bash
node -e "const fs=require('fs'),c=require('crypto');console.log(c.createHash('sha256').update(fs.readFileSync('tests/canary.js')).digest('hex'))"
```

Repository commands read this setting from `.npmauditor.json` in each selected directory root; relative paths resolve from that root. Native protected commands also honor their existing np-audit configuration, resolving those relative paths from the command's working directory. Paths must name `canary.js` inside selected roots. Wildcards, conflicting hashes and invalid records are rejected. There are at most 128 distinct exceptions; configuration reads are bounded to 128 KiB per file and file verification to 1 MiB per file, with 32 MiB read budgets.

An exact match preserves the file and its statically resolved script/hook calls. When other files are quarantined, generated ignore rules include exceptions for preserved trusted files. If the content changes, the hash no longer matches: the exception stops applying and normal protection handles the file. Updating a legitimate canary requires reviewing its new contents and deliberately updating its hash. Hashes are never refreshed automatically.

Reports retain indicators and behavior evidence even for trusted files. `trust.files` records matched, changed, missing, unscanned or unverified files; protection also records pre-action trust status. An exception expresses the configured user's decision. Neither a filename nor a matching hash proves a file benign or malicious. Existing behavior matches remain review findings, not automatic malware verdicts.

## Monitor selected folders

```bash
node bin/npa.js canary-monitor /path/to/project
node bin/npa.js canary-monitor /srv/app /dev/shm --json
```

Starting the monitor runs protection immediately. It watches the selected directory roots and automatically reuses the same repair, quarantine, ignore and trusted-file logic after changes. There is no second quarantine switch. It also rechecks every five seconds to detect persistent files missed by notifications, and groups nearby change events to avoid repeated scans. Duplicate reports are suppressed. `--interval <milliseconds>` changes the periodic interval from 200 to 300000 milliseconds.

The monitor runs in the foreground until Ctrl+C. No service, automatic startup, shell profile or deployment configuration is installed. For observation without file changes, add `--read-only`. Monitoring uses the bounded protection profile: filenames throughout selected roots, with content reads for manifests, hooks, Git configuration and canary files. Use the standalone full scan for behavior searches in renamed files.

`--json` emits one JSON record per changed report or error. Watch failures are explicit; periodic checks continue, and monitoring coverage remains incomplete. Missing roots, unreadable paths and scan limits are reported. Quarantine storage is excluded from analysis and does not trigger monitor scans.

In plain English: a monitor sees that a file appeared and then reacts. Another process could run the file before that reaction. The existing command guard checks before commands np-audit launches; monitoring adds arrival detection but does not replace that guard or guarantee zero execution. Node's [watcher documentation](https://nodejs.org/api/fs.html#caveats) documents platform and notification limitations. Files created and removed between checks may escape observation.

Trusted-file and monitor tests verify preserved intentional files/calls, changed-hash quarantine, mixed trusted/untrusted ignore rules, periodic fallback, shutdown and no subprocess/network activity inside monitoring. The live regression test runs actual protected npm `prefix` commands and actual foreground monitor processes, introduces inert files after startup, verifies automatic quarantine and verifies read-only preservation. No scanned fixture script or hook is executed.

The [observed Windows trust and monitor results](validation/canary-killer/cda0b79-windows-trust-monitor.md) retain the actual npm output, monitor reports and filesystem observations for implementation `cda0b79`.

## Check before Node entrypoints run

Protected np-audit npm launches automatically prepend the startup guard to `NODE_OPTIONS`. Descendant Node processes that inherit this environment repeat protection before loading their entrypoint. This uses the same bounded protection and trusted-file policy, with no second enable flag on protected npm launches. An already active session guard also applies when the native `canaryProtection` setting is false; forwarding npm preserves that session environment. Protected child launches retain the inherited selected roots.

Direct Node commands need the documented session settings below, either applied in the current terminal or inherited from a configured parent process. np-audit does not install system profiles or services. Protected npm launches through np-audit receive the guard automatically.

To configure direct Node commands for explicitly selected folders, generate the session settings:

```bash
node bin/npa.js canary-guard /path/to/project
```

Apply the two printed assignments in the same terminal. Windows output uses PowerShell assignments; other platforms use shell `export` assignments. These set `NPA_CANARY_GUARD` and `NODE_OPTIONS` for that session. `--json` returns the environment values and setup lines without applying them. The command itself only prints configuration; a Node process already using startup protection still runs its configured check first. No service, profile, system setting or global installation is changed.

The guard runs through Node's `--require` startup mechanism, before the main entrypoint. It checks the configured roots and preserves exact trusted canaries. Failed protection, invalid guard configuration, or an unscoped direct `canary.js` entrypoint stops startup with exit `2`. If the canary entrypoint was quarantined, startup stops instead of loading it. Existing `NODE_OPTIONS` are retained after the guard's preload. Trusted-file configuration reads are bounded to 128 KiB per file; serialized root configuration is bounded to 64 KiB.

This covers configured Node starts, including absolute-path Node invocations and children that retain the environment. Clearing `NODE_OPTIONS`, replacing a child's environment, using a different runtime or running non-Node shell commands bypasses this integration. It is not an operating-system execution policy. It does not prevent a file introduced after startup from being read or executed by code already running, and it does not remove concurrent filesystem races. The check before entrypoint loading is stronger than watching for a later notification, but is not a guarantee of zero execution through every route.

Live tests use harmless inline Node entrypoints that write a marker; no scanned fixture script or canary is executed. They verify protection before that marker, failed protection leaving the marker absent, exact trusted-file preservation, changed-file quarantine, inherited child checks, guard ordering before an existing preload, generated session settings, and actual npm startup catching a file introduced after preflight. The native timing case injects an inert file immediately before forwarding the real npm spawn; it does not substitute a scanner or npm result.

The [observed Windows Node startup results](validation/canary-killer/760a3f8-windows-node-startup.md) retain the real-process output and entrypoint observations for implementation `760a3f8`.

## Scope and reporting

Supply every standalone scan root explicitly. Paths and repeated `--exclude <path>` options resolve from the current directory. Temporary directories, hidden files, untracked files and `node_modules` are scanned when present under supplied roots; there is no name-based exclusion for `/dev/shm` or `/tmp`. A root may also be an individual regular file. The default repository command only reads local files; `--quarantine` permits the actions above. Neither repository-command mode invokes npm, Git, hooks, scanned scripts, downloads or repository-configured external commands, or runs registry, vulnerability or update checks. Automatic protection also performs its checks without subprocesses or network calls; after successful protection, the controlled command continues with its normal audit/npm behavior.

The scan examines all `package.json` scripts (including build and preparation), resolves recognizable literal local interpreter/direct-script targets, and records existing, missing and unresolved references. Local JavaScript imports use np-audit's existing import extraction and a limited extension/index search. It reads local `.git/config`, `config.worktree`, unconditional literal includes, `.git` worktree pointers and `commondir`, and inspects default and configured `core.hooksPath` directories. Paths outside supplied roots require another explicit root. Versioned `.husky`/`.githooks` files are also inspected as text. System/global Git configuration, environment overrides, conditional includes, runtime options with complex resolution, inline JavaScript local-import resolution, package-name imports, arbitrary shell syntax and full Node module resolution are unsupported; dynamic and unrecognized command entry points are reported as unresolved. A bare Git repository is not inferred from an ordinary directory root.

Behavior findings explain download-to-shell pipelines/substitutions, saved downloads passed to shells, host/user/environment collection alongside network primitives, and commands that write scripts or assign executable permissions after file creation. Collection/network co-occurrence does not prove data flow. Matching is heuristic and can flag comments, quoted examples, test fixtures and legitimate setup tools. Renamed files are inspected by content; `canary.js` is an informational search indicator, never proof of malware. `package.jsonl` is a nonstandard text file and is never parsed as an npm manifest. Reports do not attribute the motivating incident or establish a connection to published malware cases.

JSON and text reports include absolute paths, source lines, bounded evidence, reference targets/statuses, inspected paths, unreadable paths, exclusions, hook/config coverage and limitations. Evidence is capped at 240 characters with an explicit truncation flag; terminal control characters are escaped in text output. The scan is bounded to 10,000 text files, 20,000 traversal entries, 1 MiB per file, a 32 MiB content budget (plus one-byte overflow checks), 2,000 finding/reference/gap/configuration records and 100 directory levels. Symlinks/reparse points and special files are not followed; binary/non-UTF-8 content and Git metadata other than hook/config files and pointers are excluded and reported. A limit, exclusion, read failure or unresolved reference makes coverage **incomplete**. Git checkouts normally report incomplete coverage because Git object/index metadata is deliberately excluded. Output never labels a repository clean.

Quarantine uses two bounded scan passes. Filename discovery also records regular `canary.js` files whose contents cannot be analyzed; `--quarantine` can move them without reading their contents, while retaining the original coverage gap. Ignore-file reads are limited to 128 KiB per file and 32 MiB total per action pass. Oversized or unsupported ignore files and filesystem failures are reported as failed actions.

Protection regression tests verify preserved build commands, removed prepare/hook calls, missing targets, ambiguous-command blocking and action failures. Mocked CLI tests record npm launches and assert protection finishes before launch, including a file introduced during auditing. The live integration test runs the actual CLI, dependency audit and npm: it verifies read-only scanning, quarantine with an explicit temporary root, protected `scan`, `npm prefix`, dependency-free offline `install`/`ci`, and failure blocking. npm scripts are disabled; fixture scripts, hooks and downloaded content are never executed. These tests do not verify a real application build, deployment or host integrity.

Protected Windows npm launches use the installed `npm-cli.js` entry point beside Node or a PATH directory, passing arguments directly to Node. This avoids attempting to spawn `npm.cmd` without a shell. A missing compatible npm entry point or a failed launch returns an error. Nonstandard Windows npm wrapper layouts are unsupported by this protected launch path.

The [Windows live validation record](validation/canary-killer/README.md) documents observed results for commit `94fc955`, including the unchanged raw stdout/stderr and filesystem observations. It distinguishes real npm operations with scripts disabled from mocked launch tests and untested build/deployment behavior.

Exit codes are `0` for complete coverage without behavior-review findings, `1` for behavior-review findings, and `2` for incomplete coverage or invalid arguments (`2` takes precedence). Informational canary/nonstandard-file indicators alone do not cause exit `1`. A GitHub repository is supported through its local checkout: the scan cannot inspect another machine's untracked files or local `.git/hooks`. No scan establishes host integrity, recovers deleted content or reconstructs a previously executed payload. For consistent results, scan a stable filesystem snapshot; this is not a hardened forensic reader for a concurrently changing hostile filesystem.

## Incident-derived reconstruction

The [incident-derived reconstruction fixtures](../test/fixtures/incident-derived-reconstruction/README.md) preserve the confirmed `package.json` build and prepare references, provide inert download-to-shell text at a reserved `.invalid` URL, and include a representative Git hook. A second state leaves the manifest and hook references intact after `canary.js` is removed. An additional temporary-directory fixture represents the reported file under `/dev/shm` and is scanned only when its root is explicitly supplied.

The [regression test](../test/unit/incident-derived-reconstruction.test.js) verifies existing/missing targets, paths, lines, evidence, configured hooks, behavior matches and incomplete coverage. It asserts unchanged inputs and zero subprocess or network calls during scanning. It never runs the fixture's build, prepare, canary or hook. From the np-audit checkout, run only the test harness:

```bash
node test/unit/incident-derived-reconstruction.test.js
```

This is an incident-derived reconstruction, not an exact reproduction. The original payload, effects, origin and full original hook behavior remain unknown. The supplied incident record supports the historical HTTP-to-Bash description. Read-only inspection of the linked [current canary source](https://github.com/electricwolfemarshmallowhypertext/stateful-ai-research/blob/main/canary.js) confirms `child_process.exec` with a hardcoded HTTP download piped to Bash and `|| true`, but does not reconstruct the historical fetched content. The webhook was not contacted and the source was not executed. Tests validate detection against known characteristics; they do not prove compromise.

## Supporting advisories

- [OSV MAL-2026-17642](https://osv.dev/vulnerability/MAL-2026-17642): an install hook ran `canary.js` and transmitted host/user and CI information.
- [GHSA-p77h-h8r5-pv82](https://github.com/advisories/GHSA-p77h-h8r5-pv82): an install hook ran `src/canary.js` to send network beacons.

These advisories document comparable attack patterns. Detection here is grounded in the verified current `canary.js` download-to-Bash command and `package.json` build/prepare references, together with the supplied incident record. The historical fetched payload and full original hook behavior remain unknown.
