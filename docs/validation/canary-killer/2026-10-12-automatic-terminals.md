# Automatic Windows terminal activation: observed results

Automatic activation is installed for this Windows user's normal PowerShell and CMD terminals. Fresh terminals select the current project and apply Canary Killer without a helper command or supplied folder path.

Tested implementation: [`eedea7913ee837545168f319b9efc656c8663471`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/eedea7913ee837545168f319b9efc656c8663471), on 2026-10-12, Node 24.16.0, npm 11.13.0, Windows PowerShell 5.1.26100.9444 and PowerShell 7.6.5.

The [raw record](2026-10-12-automatic-terminals-real-results.json) contains real stdout/stderr, exits, executable paths, filesystem observations, source SHA-256 hashes, installed profile hashes, CMD registry values and the full test-suite output. Its SHA-256 is `00005a3e44c45ca7d878ce54cfb164c41668baa169f60e8ce54d3b0a499eefa8`.

## Real-process verification

The [live test](../../../test/e2e/canary-terminal-auto-live.test.js) launched fresh normal terminals with empty parent `NODE_OPTIONS` and `NPA_CANARY_GUARD`. PowerShell did not use `-NoProfile`; CMD did not use `/d` for startup. Test drivers did not invoke the session helper. Application processes, protection and npm results were not mocked.

| Check | Actual cases | Observed result |
| --- | ---: | --- |
| Canary present when terminal opens | 3 | Windows PowerShell, PowerShell 7 and CMD quarantined it; harmless Node entrypoint ran afterward, exit 0 |
| Change directory, then introduce a canary | 3 | Each terminal's next absolute-path Node launch protected the new current project before its entrypoint ran, exit 0 |
| Protection fails because `.gitignore` is a directory | 3 | Node returned 2; entrypoint marker absent; canary remained |
| Ordinary `cmd` launch from automatically activated PowerShell | 2 | Preflight quarantined the canary before a harmless echo command, exit 0 |
| Failed protection before that shell launch | 2 | Returned 2; shell marker absent; canary remained |
| Direct native npm `prefix` | 3 | Actual npm printed each project's directory, exit 0; canary quarantined |

In the successful Node cases, `build` changed from `node canary.js && tsc` to `tsc`; the canary-only `prepare` entry disappeared. The representative hook retained its trusted canary call and `echo preserved`. Ignore rules were present, quarantine payload hashes matched the original inert inputs, and exact trusted-canary hashes stayed unchanged.

A fresh automatically activated terminal in the actual np-audit checkout also completed a harmless inline Node entrypoint with exit 0. Before/after SHA-256 hashes matched for all six reconstruction inputs, including intentional missing-target references. Those sources use exact reviewed hash exceptions; they still appear in scan evidence and do not make incomplete coverage clean.

## Installation and regressions

The installed settings are the current user's `Documents/PowerShell/profile.ps1`, `Documents/WindowsPowerShell/profile.ps1` and `HKCU\Software\Microsoft\Command Processor\AutoRun`. The CMD value references `E:\np-audit\bin\enable-canary.cmd` and the installed Node executable. No old loader-name references remain in source or these installed settings. The registry records that AutoRun was absent before installation.

The full suite passed **34 test files, 0 failures** before the implementation commit. The 16-case live test was then rerun against that committed implementation for this raw record. Isolated installer regressions verified absent-profile handling, preservation of original bytes, repeat-install idempotence and uninstall restoration without changing the live registry. Root-selection and trust regressions verified automatic selection, preservation of intentional reference fixtures, changed-hash loss of exceptions and quarantine of targets even when their reference source is trusted.

These are **incident-derived reconstructions**: canaries contain comments and reserved `.invalid` URLs. No scanned fixture script, hook, canary or downloaded content was executed. The harmless drivers were outside scanned roots; Node entrypoints were inline marker writers. npm ran `prefix`, which does not run package scripts. Existing suite tests include their own local mock-registry traffic; this record does not claim the whole test suite makes zero network calls.

## Coverage boundary

Already-open terminals retain their previous environment; reopen them to load startup activation. Commands that deliberately skip profiles/AutoRun without inherited guard settings, clear `NODE_OPTIONS`, or bypass selected non-Node launcher functions/macros are outside this integration. CMD macros apply to interactive commands. Bash/WSL execution was not tested. This proves current-user startup activation and the listed real launches, not universal execution blocking, recovery of the historical payload or host integrity.
