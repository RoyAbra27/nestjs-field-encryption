# Contributing

Issues and PRs welcome.

1. Fork and clone the repo.
2. `npm install`
3. Write a failing test for your change, then make it pass.
4. `npm test` and `npm run build` must both be green before opening a PR.
5. Keep PRs focused - one behavior change per PR.

For anything touching the cipher core (`dek-cipher.ts`) or key handling
(`kms-key-provider.ts`), explain the threat model change in the PR
description, not just the code diff.

## Reporting a bug

Open an issue with a minimal reproduction. For security vulnerabilities,
see [SECURITY.md](SECURITY.md) instead - do not open a public issue.
