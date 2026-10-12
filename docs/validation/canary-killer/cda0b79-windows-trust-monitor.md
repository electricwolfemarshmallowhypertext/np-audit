# Trusted canaries and folder monitoring: observed Windows results

Date: 2026-10-12. Tested implementation: [`cda0b79`](https://github.com/electricwolfemarshmallowhypertext/np-audit/commit/cda0b794e4eb1684fba427ca606b3c51add74a86). Runtime: Windows, Node.js 24.16.0, npm 11.13.0.

The [recorded results](cda0b79-windows-trust-monitor-real-results.json) contain actual npm stdout/stderr, parsed monitor JSON reports, filesystem observations and SHA-256 hashes of the tested source files. The committed live regression test ran without scanner, process-launch or watcher mocks. It returned seven observations, including both monitor sessions.

| Check | Observed result |
| --- | --- |
| Exact trusted file during a native protected npm launch | npm `prefix` exited `0`; the file, build/prepare calls and hook remained unchanged; no ignore file was created |
| Content changed at the trusted path | The old hash stopped matching; the file was quarantined, canary calls were removed, `build: tsc` remained, and actual npm `prefix` exited `0` |
| New untrusted canary introduced after monitor startup | Automatically quarantined; its manifest/hook calls removed; the separate trusted file and its calls preserved |
| Trusted file changed while monitoring | Pre-action report recorded `changed`; the file was quarantined and its calls removed |
| New file during explicit read-only monitoring | Reported and left in place; manifest, hook and ignore state remained unchanged |

The real arrival was observed quarantined after 250 milliseconds in this run, with a 5000-millisecond periodic interval. The actual watcher was registered before introduction. This is an observed timing, not a guaranteed response time. Starting the monitor applied protection automatically; no quarantine flag was supplied. The mixed case's ignore block preserved the trusted file with `!/legit/canary.js`.

Both foreground monitor processes were terminated by the test and their termination recorded. The temporary test projects were then removed. The recorded paths describe those original test locations; they are not retained projects or a live VPS.

The full suite passed 28 test files. Separate unit tests verified exact pins, changed pins, invalid records, mixed trusted/untrusted handling, retained review evidence, periodic fallback when watch registration was deliberately made unavailable, read-only behavior and stopping the monitor's periodic work. Monitor unit tests intercepted subprocess/network entry points and observed zero calls. Those unit results are separate from the live JSON record.

## Meaning in plain English

An intentional canary stays intact only while its configured path and file hash match. Changing the file removes that exception. The monitor automatically handles new untrusted canaries in selected folders while it is running.

All test canaries contained inert comments. Their changed content and download-to-shell examples were never executed. npm was used only for offline `prefix` queries with scripts disabled. These results demonstrate the trust and quarantine policy; they do not establish malware verdicts, execute builds or prove host integrity.

A monitor notices an arrival and then reacts. Another process could execute that file before the reaction. This test did not establish prevention of that race, universal command interception, Linux/macOS watcher behavior, production performance or deployment protection. No background service or shell integration was installed.

## Repeat the live checks

From the np-audit checkout:

```bash
node test/e2e/canary-trust-monitor-live.test.js
```

The test starts actual CLI/npm processes and actual foreground monitors against temporary projects. No scanned script or hook is run.
