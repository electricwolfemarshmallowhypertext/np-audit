# Canary Killer validation records

- [Direct Node PowerShell session setup (2026-10-12)](2026-10-12-powershell-session.md), with [recorded real-process results](2026-10-12-powershell-session-real-results.json).
- [Step 3: foreground monitor (2026-10-12)](2026-10-12-step3.md), with [recorded live arrival and session results](2026-10-12-step3-live-results.json).
- [Step 2: repair, quarantine and ignore (2026-10-12)](2026-10-12-step2.md), with [recorded real CLI results](2026-10-12-step2-real-results.json).
- [Explicit exceptions for intentional local fixtures (2026-10-12)](2026-10-12-explicit-fixture-trust.md), with [recorded real CLI results](2026-10-12-explicit-fixture-trust-real-results.json).
- [Node checks before entrypoints on Windows (`760a3f8`)](760a3f8-windows-node-startup.md), with [recorded real-process results](760a3f8-windows-node-startup-real-results.json).
- [Trusted files and automatic folder monitoring on Windows (`cda0b79`)](cda0b79-windows-trust-monitor.md), with [recorded npm/monitor results](cda0b79-windows-trust-monitor-real-results.json).
- [Initial Windows scan-time integration (`94fc955`)](#windows-live-validation-2026-10-12), detailed below.

## Windows live validation: 2026-10-12

The scan-time protection implementation passed the live integration test on Windows using Node.js 24.16.0 and npm 11.13.0. These results apply to implementation commit [`94fc955`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/94fc955c70f0114c1af4fbcd5f7e40c2b8a8efda).

The [raw results](94fc955-windows-real-results.json) contain eight runs with actual stdout, stderr, exit codes, paths and filesystem observations. The original JSON was copied unchanged from temporary storage. The source test's SHA-256 is recorded in that JSON.

Raw report SHA-256:

```text
5674bf853f2e03d045e060cc7ee755c6edb32741049b667030263ba5ba4f88c4
```

### Method

The [committed live test](../../../test/e2e/canary-protection-live.test.js) was rerun with observation logging added in memory. np-audit's application code, dependency scanner and npm launches were not mocked. The test created isolated, dependency-free temporary projects and representative hooks. Canary inputs contained only inert comments with a reserved `.invalid` URL.

npm ran offline with scripts disabled. No canary source, scanned fixture script, hook or downloaded content was executed. The test checked the real filesystem and removed its temporary projects after its assertions. The raw record preserves their original paths; those paths no longer identify retained test projects. The `residue/dev/shm` directory was a Windows temporary-directory fixture, not a live VPS or Linux `/dev/shm` mount.

### Observed results

| Check | Exit | Verified observation |
| --- | ---: | --- |
| Read-only repository scan | 2 | Download-to-Bash text found at `canary.js:2`; build, prepare and hook references all resolved to existing targets; input hashes unchanged |
| Quarantine with an explicit temporary root | 2 | Both canary files moved; protection reported `allowed: true`; repository calls repaired and ignore rules added |
| Native `scan` with protection enabled | 0 | Repository canary quarantined and manifest/hook calls repaired |
| npm `prefix` forwarded through np-audit | 0 | Actual npm printed the test project's directory after protection |
| Native offline `install` | 0 | Actual npm created `package-lock.json`; reported `up to date in 185ms` |
| Native offline `ci` | 0 | Actual npm removed the deliberately stale `node_modules` marker; reported `up to date in 207ms` |
| Ambiguous `node canary.js || tsc` command | 2 | Installation blocked; manifest command preserved; no lockfile created |
| Invalid `.gitignore` target: a directory | 2 | Installation blocked with `.gitignore is not a regular file`; canary remained at its original path; no lockfile created |

All committed live-test assertions passed. The earlier full test suite also passed all 25 test files from a fresh staged-file export, excluding the ignored local TODO and canary files. That earlier suite result is separate from this eight-run raw record.

### Verified repairs

Before:

```json
{"build":"node canary.js && tsc","prepare":"node canary.js"}
```

After:

```json
{"build":"tsc"}
```

The representative hook's `node canary.js` line was removed; its `echo preserved` line remained. `.gitignore` received `canary.js` and `.np-audit-quarantine/` entries. The repository's quarantined content matched its original inert input.

### Meaning and limits

Standalone repository scans returned `2` because overall coverage remained incomplete, including excluded Git metadata and the unresolved `tsc` command. Successful canary protection does not make that scan clean. Native scan/install/ci exit codes describe their command results; detailed protection coverage remains in their reports.

These results verify scan-time detection, repair, quarantine, ignore updates, successful real npm launches and failure blocking in the tested Windows environment. They do not verify execution of `tsc`, an application build, installation of external dependencies, deployment, host integrity, continuous monitoring or interception of commands launched outside np-audit. At that tested revision, Node startup and additional shell integration remained future work. The later Node startup results are linked above.

### Repeat the live test

From a checkout containing the implementation, with Node.js and npm available:

```bash
node test/e2e/canary-protection-live.test.js
```

This runs real CLI/npm processes offline with scripts disabled. It prints a pass summary; the detailed JSON here was captured through additional observation logging. Future validation runs should retain their own dated records rather than overwrite this observation.
