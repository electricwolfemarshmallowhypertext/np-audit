# Node startup protection: observed Windows results

Date: 2026-10-12. Tested implementation: [`760a3f8`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/760a3f835128f31b58f5a6fafbdbeaeb2241c85c). Runtime: Windows, Node.js 24.16.0, npm 11.13.0.

The [recorded results](760a3f8-windows-node-startup-real-results.json) retain ten real-process cases, actual stdout/stderr, entrypoint markers, filesystem observations and hashes of the tested source files. Node was invoked by its actual absolute executable path. The test used harmless inline entrypoints; no scanned canary script or hook was executed.

| Check | Exit | Observed result |
| --- | ---: | --- |
| Protection before an inline entrypoint | 0 | Entrypoint marker recorded the canary already absent and `build: tsc` already repaired |
| Failed protection | 2 | Entrypoint marker was absent; the canary remained; startup reported failure |
| Exact trusted file | 0 | Entrypoint marker recorded the canary present; its original hash and build/prepare calls stayed intact |
| Previously trusted file changed | 0 | Changed file was quarantined before the inline entrypoint observed it |
| File introduced after parent startup | 0 | A real child Node process inherited the guard, quarantined the file and repaired calls before its inline entrypoint |
| Existing additional preload | 0 | Additional preload ran only after the canary was removed; existing Node options were preserved |
| Invalid startup settings | 2 | Node stopped before the inline entrypoint wrote a marker |
| Generated session settings | 0 | Printing settings left inputs unchanged; applying those settings to an actual Node process enabled the pre-entrypoint check |
| File introduced after native np-audit preflight | 0 | Automatic guard quarantined the newly introduced file at actual npm startup; actual npm `prefix` printed the correct project path |
| Active session guard with native protection disabled | 0 | Guard quarantined the file and actual npm printed the correct project path without a second native enable flag |

The post-preflight case used an explicit timing-injection wrapper: it wrote inert canary text immediately before forwarding the genuine npm spawn. The wrapper did not substitute a scanner result, npm process or npm result. npm ran offline with scripts disabled. Temporary test projects were removed after the assertions.

## What this proves

The startup check runs before the tested harmless entrypoints. Failed protection prevents those entrypoints from running. Configured inherited child Node processes repeat the check and can catch files introduced after their parent began. Native protected npm launches automatically receive this guard, without another enable flag. Trusted canaries remain exempt only when their configured path and hash match.

This closes the tested interval between np-audit preflight and Node entrypoint startup. It does not prove prevention for every execution route. Clearing `NODE_OPTIONS`, replacing a child environment, non-Node programs and file changes after an existing process has started remain outside the demonstrated guarantee. Concurrent filesystem races, real application builds, deployments and Linux/macOS behavior were not verified. No shell profile, background service or host-wide execution policy was installed.

All 29 test files passed on this implementation. The raw JSON records the ten startup cases and the full-suite command, isolated environment, exit status and summary.

## Repeat the real checks

From the np-audit checkout:

```bash
node test/e2e/canary-startup-live.test.js
```

This runs real Node/npm processes against temporary projects. It never executes the scanned canary files or fixture hooks.
