![np-audit](docs/title-image.png)

# np-audit

**Check npm packages before installing them. Find and quarantine unwanted canary files in your projects.**

[Technical architecture](docs/TECHNICAL_ARCHITECTURE.md) | [Canary Killer guide](docs/CANARY_KILLER_TECHNICAL.md) | [Verified results](docs/validation/canary-killer/README.md)

## Check packages

From this checkout, with Node.js 18 or newer:

```bash
node bin/npa.js scan express
```

np-audit reads package code and reports suspicious patterns and known vulnerabilities. Its install commands check packages before handing installation to npm.

## Canary Killer

**Find it. Remove its confirmed script calls. Quarantine it. Add Git ignore rules.**

Scan a project without changing files, or add `--quarantine` to apply protection:

```bash
node bin/npa.js canary-killer ../my-project
node bin/npa.js canary-killer ../my-project --quarantine
```

Intentional canaries can be preserved with reviewed file exceptions. [Watch folders or activate automatic Windows terminal protection](docs/CANARY_KILLER_TECHNICAL.md).

[Command reference and configuration](docs/TECHNICAL_ARCHITECTURE.md#usage) | [Contributing](CONTRIBUTING.md) | [MIT license](LICENSE)
