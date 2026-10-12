# Incident-derived reconstruction

These harmless fixtures validate detection against known incident characteristics. They are an incident-derived reconstruction, not an exact reproduction. The original fetched payload, its effects and origin, and the full original hook behavior remain unknown. Passing these tests does not prove compromise or establish host integrity.

The supplied incident record confirmed these references in `package.json`, not `package.js`:

```json
"build": "node canary.js && tsc",
"prepare": "node canary.js"
```

The record describes HTTP content passed to Bash during a root build. That historical behavior is supported by the supplied record; the original incident-time source was not independently inspected. The payload served by the remote endpoint is not available to this reconstruction.

Read-only inspection on October 12, 2026 of the linked [stateful-ai-research/canary.js](https://github.com/electricwolfemarshmallowhypertext/stateful-ai-research/blob/main/canary.js) confirmed source text using Node's `child_process.exec` to invoke `curl` against a hardcoded HTTP webhook, pipe the response to Bash, and suppress failures with `|| true`. The Git blob SHA returned for that source was `6189064cc7bfa9ff2abe2dedf426868e52a199f5`. Its [current package.json](https://github.com/electricwolfemarshmallowhypertext/stateful-ai-research/blob/main/package.json) also contained the build and prepare references above. Neither file was executed, and the webhook was not contacted. This verifies the linked source text; it does not establish which payload ran during the historical incident or recover the original hooks.

Additional manifest references in sticky, innerverse, presence-engine-home and pe-frontend-chat were supplied by the reporter. This reconstruction does not independently inspect those repositories.

## Fixture states

| State | Contents | Purpose |
| --- | --- | --- |
| `present/` | Exact manifest commands, generated inert `canary.js` text, representative `.githooks/pre-commit`, and `git-config.txt` | Detect existing targets and download-to-shell text |
| `removed/` | Identical manifest, hook and configuration; no `canary.js` | Detect references left after deletion |
| Generated `temporary/dev/shm/` | Inert `canary.js` residue in the test's temporary directory | Represent the reported temporary file and verify an explicitly supplied additional root |

The hook is representative text, not recovered original content. `canary.js` contains comments only, using a reserved `.invalid` URL; it performs no operations. The temporary file's text is invented test data, not recovered `/dev/shm` content. Never run fixture scripts, builds, preparation commands or hooks.

The regression test copies the manifest, hook and configuration fixtures into an isolated temporary directory and generates the inert `canary.js` inputs there. Local canary files remain ignored; the test does not depend on them being present after checkout. It materializes `git-config.txt` as local `.git/config` so the scanner can inspect configured hooks without invoking Git. The test scans the present state, removes only its temporary copy of `canary.js`, and rescans the remaining references. It compares that result with the checked-in removed state. The temporary residue is outside the repository root and is inspected only when explicitly supplied as a second root. This models the path shape on the test platform; it does not inspect a live VPS or an actual Linux `/dev/shm` mount.

Assertions check paths, lines, evidence, existing/missing target status, configured hook coverage, download-to-shell matches, unchanged scan inputs and incomplete coverage. Subprocess, HTTP, fetch, socket, TLS and DNS entry points are intercepted during scanning; every scan must make zero calls. `tsc` remains an unresolved command entry point, and excluded Git metadata is reported. Those gaps must not be labeled clean.

## Supporting advisories

- [OSV MAL-2026-17642](https://osv.dev/vulnerability/MAL-2026-17642) describes an install hook running `canary.js` and collecting host/user and CI information for outbound transmission.
- [GHSA-p77h-h8r5-pv82](https://github.com/advisories/GHSA-p77h-h8r5-pv82) describes a postinstall hook running `src/canary.js` to send network beacons.

These advisories document comparable attack patterns. The current `canary.js` download-to-Bash command and `package.json` build/prepare references were verified.
