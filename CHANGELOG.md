# Changelog

All notable changes to this project are documented here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/).

## [0.1.0] - Unreleased

### Added
- Initial release: AES-256-CBC cipher core, KMS envelope-encryption key
  provider, `@Encrypt()` field decorator with recursive tagged-field
  traversal, NestJS `EncryptPipe`/`DecryptInterceptor` HTTP integration, and
  a schema-agnostic Prisma write-encryption extension.
