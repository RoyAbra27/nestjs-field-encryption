# Security Policy

This library handles encryption keys and ciphertext. If you find a security
vulnerability (a way to decrypt data without the key, a padding oracle, a
timing side-channel, a way to bypass the idempotency check and leak an IV
reuse, etc.), please do **not** open a public issue.

Email <roy.ab27@gmail.com> with details and, if possible, a minimal
reproduction. Expect acknowledgment within 5 business days; I'll aim to ship
a fix before any public disclosure.

## Supported versions

Only the latest version published on npm receives security fixes.

## Scope

This library implements field-level encryption and a KMS-backed key
provider. It does not implement key rotation, and does not protect against
a compromised KMS key or database — see `docs/architecture.md` for the full
threat-model writeup and known gaps.
