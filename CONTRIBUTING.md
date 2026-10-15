# Contributing

Use Node.js 20 or 22 and Git. Install with `npm ci --ignore-scripts`, then run `npm run check`. `npm run typecheck`, `npm test` and `npm run build` can also run individually. Tests create isolated temporary repositories below `.tmp/` and clean them up; they never contact GitHub or use your repositories.

Open a sanitized bug report with the version, rule ID, exact command and smallest reproducer. Security disclosures belong in the private channel described in SECURITY.md. Do not paste real secrets, even into tests.

For detection changes, include both a triggering case and a safe case. Assert rule, severity and useful location. Add integration coverage when changing index reads, configuration, protocol behavior or escaping. Avoid network-dependent tests and keep production dependencies small. Build runtime patterns from synthetic fragments rather than committing realistic token strings. Document false-positive tradeoffs and record user-facing changes in CHANGELOG.md.

Before submitting, run `npm run check`, `node dist/cli.js scan --fail-on warn` and `npm pack --dry-run`. CI verifies Node 20/22 on Linux, Windows and macOS. Keep pull requests focused and explain the concrete problem, resulting behavior and validation.

Releases require a matching version/tag, a configured npm trusted publisher, and the `npm` environment. Maintainers should require review for workflow, dependency and ignore-policy changes. Review the packed files before publishing; never commit access tokens or generated credentials. The composite action builds from locked source instead of checking in a second compiled implementation.
