# Extended Windows shell protection: observed results

Implementation [`8890eee27f8a6f4ac6d4fd30ad10ecd5f9e24768`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/8890eee27f8a6f4ac6d4fd30ad10ecd5f9e24768) passed 51 new real-process cases. The existing 16-case automatic-terminal test also passed against that commit. The full suite passed 35 test files before the implementation commit.

Observed on 2026-10-12: Windows, Node 24.16.0, Windows PowerShell 5.1.26100.9444, PowerShell 7.6.5 and Git Bash 5.3.9 (`x86_64-pc-cygwin`). macOS was deferred as requested. An actual Ubuntu WSL probe printed `NPA_NODE_ABSENT`; native Linux Node protection was not validated or installed.

[Raw process and filesystem evidence](2026-10-12-shell-paths-real-results.json), SHA-256: `82e64ca8eaea89c6a06dba58bb2d635836c20fd02651fe8fa76b75ad77bdf05e`.

## Implemented checks

PowerShell now uses command lookup in addition to launcher functions. It checks application/script paths and resolved `Start-Process`/`Invoke-Expression` calls. This handles full executable paths, variable-held paths, direct batch files and dot-sourced script paths in the tested sessions. Failed checks replace the requested command with a denial rather than allowing the original target to launch.

Configured Bash children receive `BASH_ENV`. The guard checks startup and checks commands through `DEBUG` with function tracing. It reuses inherited Node protection roots and stops that Bash context when checking fails. The CMD loader also supplies these settings, reading generated values as data without evaluating them as shell commands. These mechanisms are documented in the [technical architecture](../../CANARY_KILLER_TECHNICAL.md#check-before-shell-commands-launch).

| Real-process check | Cases | Observation |
| --- | ---: | --- |
| Full/variable-held CMD paths, Start-Process, Invoke-Expression, direct batch paths and dot-sourced scripts | 24 | Allowed cases returned 0 with canary removed and marker present; denied cases returned 2 with marker absent |
| Nested PowerShell dispatch and Node launched inside batch drivers | 8 | Files introduced inside the driver were handled before the protected inner command; failed protection left its marker absent |
| Git Bash commands, functions, subshells and command substitutions | 16 | Introduced canaries quarantined before marker commands; failed protection returned 2 and prevented markers |
| Git Bash launched from fresh normal CMD | 2 | AutoRun supplied the guard without a helper call; success and failure checks matched filesystem observations |
| Existing Bash startup content and removed Node guard | 1 | Harmless original startup content ran; removing NODE_OPTIONS caused the next command to be blocked, exit 2 |

Trusted canary bytes remained unchanged in the PowerShell route fixtures. Successful cases verified quarantine storage and Git ignore rules; direct-call fixtures retained `build: tsc` and removed the canary-only prepare entry. The 16 automatic-terminal cases separately checked quarantine payload hashes and hook repair. A fresh normal terminal in the actual np-audit checkout loaded the lookup/Bash settings and preserved all six reconstruction inputs by before/after hashes.

## Method

The [extended live test](../../../test/e2e/canary-shell-paths-live.test.js) uses actual PowerShell, CMD, Bash and Node processes. Application execution, protection and outcomes are not mocked. Drivers live outside scanned roots and contain harmless file creation, echo/printf commands or inline Node marker writers. Canary inputs are comments, including a reserved `.invalid` URL. No scanned canary, hook, fixture script or downloaded payload is executed. These are incident-derived reconstructions, not an exact replay of the unknown incident payload.

The raw record includes both live-test observation sets, runtime probes, committed-source hashes, installed profile hashes/registry values, checkout preservation and full suite stdout/stderr. Temporary fixture directories were removed after assertions; their paths remain as observations. Existing suite tests use local mock-registry traffic, so the record does not claim the entire suite makes zero network calls. Each Bash command check launches Node and performs bounded protection; low overhead was not benchmarked.

## Remaining routes

Direct .NET process creation, cached `CommandInfo` invocation, arbitrary non-Node commands inside running CMD, and interactive/POSIX/privileged modes are not universally intercepted. Hook/settings removal remains a bypass. Redirection/expansion timing and concurrent changes are not a universal before-execution guarantee. These checks do not establish host integrity or reverse earlier execution. Native WSL Node validation remains open; macOS is deferred. The implementation and results cover the routes listed above.
