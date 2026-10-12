# Explicit exceptions for intentional local fixtures

Observed on October 12, 2026, Windows, Node.js 24.16.0. The existing trust implementation was used without application-code changes.

The checkout contained exactly two local `canary.js` files outside dependency and Git storage. Both contain comments only. Their paths and purpose are documented in the [incident-derived reconstruction](../../../test/fixtures/incident-derived-reconstruction/README.md). The repository's [configuration](../../../.npmauditor.json) now pins their exact paths and SHA-256 hashes:

- `test/fixtures/incident-derived-reconstruction/present/canary.js`
- `test/fixtures/incident-derived-reconstruction/temporary/dev/shm/canary.js`

These exceptions preserve deliberate test inputs. They do not approve the original incident canary, remote content or another file with the same name. The local files remain ignored by Git. Their hashes are not refreshed automatically.

## Real verification

The [recorded results](2026-10-12-explicit-fixture-trust-real-results.json) retain the configuration, hashes, trust reports and before/after observations.

| Check | Observed result |
| --- | --- |
| Actual checkout, real read-only CLI scan | Both exact files reported `trusted`; observed input hashes stayed unchanged |
| Real protection CLI on an isolated copy | Both files preserved; build/prepare and representative hook bytes unchanged; zero repairs and zero quarantine actions |
| Suspicious representative text in the trusted fixture | Download-to-shell review evidence remained visible |
| Existing trust regression | Passed exact preservation, changed-hash handling, mixed ignore exceptions, invalid records and retained review evidence |

Both CLI scans returned `2` for incomplete overall coverage. Protection on the copy reported `allowed: true`; this is not a clean-scan or malware verdict. No canary, scanned script, hook or downloaded content was executed. The isolated verification project was removed after its assertions. Protection was not applied to the actual checkout.

Repeat the existing trust regression from the checkout:

```bash
node test/unit/canaryTrust.test.js
```
