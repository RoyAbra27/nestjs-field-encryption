# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-07-02

Hardening release from a full review of the encrypt/decrypt paths. Contains
behavior changes: some previously-silent conditions now throw.

### Fixed
- `FieldEncryptor.decryptTagged` no longer 500s the whole response when a
  tagged field holds a value that cannot be decrypted under the current DEK
  (empty string, legacy plaintext, or a value from a different key); the value
  is left untouched instead.
- `isEncryptedWithDek` now requires the decrypted plaintext to parse as JSON,
  closing a chance-valid-padding false positive that could cause a genuine
  plaintext value to be skipped and stored in the clear.
- `KmsKeyProvider.getDataKey` validates that the KMS-decrypted DEK is 32 bytes,
  failing clearly at the boundary instead of with a cryptic cipher error later.
- `FieldEncryptor.assertNoTaggedFieldsBeyondMaxDepth` no longer false-throws
  when a tagged field is nested inside another tagged (whole-encrypted) field.

### Changed (behavior)
- The Prisma extension (`encryptWriteArgs` / `detectPlaintextTaggedColumns`)
  now throws when a registered column is nested beyond `maxDepth`, instead of
  silently persisting it as plaintext.
- `FieldEncryptor.decryptTagged` now enforces `maxDepth` (mirroring
  `encryptTagged`), throwing instead of returning ciphertext for a tagged field
  nested too deep.

### Added
- `decryptWithDek`, the public inverse of `encryptWithDek`, and the
  `DEK_KEY_LENGTH` constant.

### Docs
- Documented that nested DTOs must use `class-transformer`'s `@Type()` so their
  `@Encrypt()`-tagged fields are encrypted (a plain nested object is silently
  left as plaintext).

## [0.1.0] - 2026-07-02

### Added
- Initial release: AES-256-CBC cipher core, KMS envelope-encryption key
  provider, `@Encrypt()` field decorator with recursive tagged-field
  traversal, NestJS `EncryptPipe`/`DecryptInterceptor` HTTP integration, and
  a schema-agnostic Prisma write-encryption extension.
