# Direct Node session setup: observed results

Observed October 12, 2026, Windows, Node.js 24.16.0, Windows PowerShell 5.1.26100.9444. Tested implementation: [`8a90ebc`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/8a90ebcbd4b319b00b8dfab0600f53a9c229ba75).

The [recorded real-process results](2026-10-12-powershell-session-real-results.json) contain actual stdout/stderr, exit codes, entrypoint observations and tested source hashes. All 30 test files passed; the suite command, environment and summary are included in the record.

## Session setup

From the checkout, run this in the PowerShell terminal used for your selected application:

```powershell
& ./bin/enable-canary-guard.ps1 -Roots C:/path/to/project
```

The helper reuses `canary-guard --json` and applies its two environment values to the current PowerShell process. Direct Node launches from that session inherit the startup guard. It preserves existing Node options. It does not alter other open terminals, profiles, user/machine environment settings or services. This follows [Microsoft's documented session scope and child-process inheritance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.5).

## Real verification

The test started actual PowerShell processes with `-NoProfile`, ran the helper, then introduced comments-only canary text and launched the actual absolute-path Node executable. The harmless inline entrypoint wrote a marker; no scanned script, canary or hook was executed.

| Check | Exit | Observation |
| --- | ---: | --- |
| Configured session, newly introduced canary | 0 | Before the inline entrypoint, canary quarantined, build reduced to `tsc`, prepare removed and hook repaired; entrypoint recorded the file absent |
| Exact trusted canary and existing options | 0 | Trusted SHA-256 and its hook/script calls preserved; existing `--trace-warnings` remained |
| Protection failure: `.gitignore` is a directory | 2 | Node stopped before entrypoint; marker absent and canary still present |
| Invalid setup root | 1 | Helper failed before introducing the test canary or launching the inline entrypoint |

The successful case also verified that quarantine preserved the original bytes and ignore rules were added. Paths containing spaces worked. Temporary test projects were removed after assertions. Only test sessions were configured; other open terminals were not changed. The earlier foreground checkout monitor was left running.

Generic shell-command interception was not implemented by this change. The guard covers Node processes inheriting these settings. Clearing or replacing the environment bypasses it. The helper was verified on Windows PowerShell 5.1; other PowerShell versions and platforms were not verified by this test. The existing manual setup output remains available. The monitor's exclusions are not copied into Node startup settings; np-audit's own source fixtures should not be mistaken for an application folder.

Repeat the live test:

```bash
node test/e2e/canary-powershell-session-live.test.js
```
