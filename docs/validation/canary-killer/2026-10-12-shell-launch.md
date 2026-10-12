# Selected shell-launch protection: observed results

Observed October 12, 2026, Windows, Node.js 24.16.0. Tested implementation: [`6857365`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/6857365f1a413f331337a3a6231729767f2bf4e4).

The missing selected-launcher integration is implemented. The existing PowerShell session helper now routes available `cmd`, `powershell`, `pwsh`, `bash` and `sh` command names through `canary-run`. That command reuses Canary Killer protection before starting the selected executable. Full-path launches can use `canary-run` explicitly. No application scanner or repair policy was replaced.

The [recorded real-process results](2026-10-12-shell-launch-real-results.json) contain actual stdout/stderr, exit statuses, command markers, preserved hashes and tested source fingerprints. All 31 test files passed on the recorded implementation.

## Real verification

| Case | Exit | Observed result |
| --- | ---: | --- |
| Real `cmd.exe` through `canary-run` | 0 | Canary removed before inline command; shell marker written; scripts/hooks repaired; trusted bytes and quarantine hashes preserved |
| Failed protection | 2 | No shell marker; canary remained; launch blocked |
| Child shell returns failure | 7 | Actual child exit code preserved |
| Literal program arguments | 0 | Child received `--json`, `--help`, `--skip`, spaces, quotes and shell metacharacters unchanged |
| Session `cmd` and PowerShell functions | 0 | Both real shell launches intercepted after separate inert file arrivals; both markers written after quarantine; trusted file preserved |
| Session launch with failed protection | 2 | Registered function blocked the launch; marker absent |

The session cases cleared `NODE_OPTIONS` after helper setup. They therefore prove the shell-launch functions performed their own preflight instead of relying on the earlier Node startup check. Each forwarded launch reinstates the Node guard in its child environment. Inputs were comments-only canaries; command markers used harmless inline shell code. No scanned canary, fixture script, hook, downloaded content or npm command was executed. Temporary projects were removed after assertions.

## Activation and scope

Run the setup helper once in each PowerShell terminal used for a selected application:

```powershell
& ./bin/enable-canary-guard.ps1 -Roots C:/path/to/project
```

It prints the launcher names it configured. Existing open terminals are separate sessions; changing this session does not change their environment or functions. [Microsoft documents session scope](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_functions?view=powershell-7.6) and [environment inheritance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.5). This implementation does not inject code into other terminals or modify profiles, services or machine settings.

This verification covers actual `cmd.exe` and Windows PowerShell launchers. Bash, sh and pwsh registration uses the same routing when available, but those runtimes were not executed in this observation. Commands bypassing the registered functions must use `canary-run`; arbitrary cmdlets, dot-sourced scripts and commands inside a shell already running are outside this pre-launch interception. It is not universal host enforcement or a way to undo earlier execution. No claim is made that every terminal on the host is protected.

Repeat the real launcher test:

```bash
node test/e2e/canary-shell-launch-live.test.js
```
