# Architecture

## Primitives

`dek-cipher.ts` implements the cipher core: AES-256-CBC with a random 16-byte
IV per encryption, base64-encoded as `IV || ciphertext`.

- `encryptWithDek(data, dek)` - JSON-serializes `data`, encrypts, and
  prepends the IV.
- `isEncryptedWithDek(value, dek)` - true only if `value` decrypts cleanly
  under `dek`. Used to make encryption idempotent: a value that already
  decrypts under the tenant's DEK is assumed to already be ciphertext and is
  left untouched.
- `looksEncrypted(value)` - a DEK-free shape check (canonical base64,
  decodes to a multiple of the block size, at least two IV lengths long).
  Used where no DEK is in scope, e.g. detecting plaintext columns before a
  database write without needing to fetch the tenant's key.

There is no key rotation and no authenticated encryption (no GCM tag). See
[Known gaps](#known-gaps).

## Write contract (encrypt-on-write)

1. A request DTO with `@Encrypt()`-tagged fields arrives at `EncryptPipe`.
2. The pipe validates the DTO with `class-validator`.
3. `FieldEncryptor.encryptTagged` walks the object graph, encrypting every
   tagged field. The DEK is fetched once per call (memoized), even if
   multiple fields are tagged.
4. The walk enforces `maxDepth` (default 5): a tagged field found deeper than
   `maxDepth` throws, rather than being silently skipped and written as
   plaintext.
5. The Prisma extension (`prisma-extension.ts`) offers the same guarantee at
   the database layer for services that write encrypted columns outside the
   HTTP request cycle (background jobs, scripts): `encryptWriteArgs` mutates
   Prisma write args in place, covering `create`, `update`, `upsert`,
   `createMany`, and nested relation writes via a caller-supplied
   `NestedWriteRelationMap`.

## Read contract (decrypt-on-read)

1. A route handler is annotated with `@TransformResponseTo(ResponseDto)`.
2. `DecryptInterceptor` reads that metadata, converts the handler's return
   value to an instance of `ResponseDto` via `class-transformer`, and calls
   `FieldEncryptor.decryptTagged` on it before the response is sent.
3. Routes without `@TransformResponseTo`, or requests where tenant
   resolution throws (e.g. an unauthenticated route), pass through
   untouched - decryption is opt-in per route, not global.

## Key management

`KmsKeyProvider` implements envelope encryption:

- Each tenant has a DEK, generated once and stored encrypted-at-rest by the
  caller via a `EncryptedKeyStore` (your own persistence - this library does
  not prescribe a storage layer).
- The DEK is encrypted under a per-tenant AWS KMS key (a key-encryption key,
  or KEK), addressed by alias: `{keyAliasPrefix}{tenantId}` (default prefix
  `alias/KEK-`).
- On `getDataKey(tenantId)`, the provider decrypts the tenant's DEK via KMS
  and optionally caches the plaintext DEK (via a caller-supplied
  `EncryptionCache`) for `cacheTtlMs` (default 10 minutes) to avoid a KMS
  round-trip on every field access. Pass `{ skipCache: true }` to force a
  fresh decrypt.

This library intentionally does not implement a two-tier cache-only vs.
decrypt-and-cache split - that was a source-project-specific optimization
tied to a request-scoped cache-warming middleware. Callers needing that kind
of pre-warming can build it on top of `EncryptionCache`.

## Failure handling

- `KmsKeyProvider.getDataKey` throws if the key store has no encrypted DEK
  for the tenant, or if KMS returns no plaintext - callers should treat both
  as request-level failures (5xx), not silently skip encryption.
- `FieldEncryptor.encryptTagged` throws if a tagged field is found beyond
  `maxDepth`, rather than silently writing plaintext. The Prisma extension's
  `encryptWriteArgs` / `detectPlaintextTaggedColumns` apply the same guard to
  registered columns nested beyond `maxDepth` in a write payload.
- `DecryptInterceptor` swallows only two specific, expected conditions:
  excluded routes and tenant-resolution failures (e.g. no authenticated
  tenant on a public route). Any other error during decryption propagates.

## Checklist: adding a new encrypted field

1. Add `@Encrypt()` to the DTO/entity property.
   - If the property lives on a **nested** DTO reached through the HTTP pipe,
     the parent's property MUST carry `@Type(() => NestedClass)`. `FieldEncryptor`
     reads the tag off the class prototype, so a nested value only encrypts when
     `class-transformer` has instantiated it; a plain nested object (no `@Type()`)
     has its tagged fields silently written as plaintext.
2. If the field is written outside the HTTP pipe (a background job, a
   script, a seed), make sure that write path also goes through
   `FieldEncryptor.encryptTagged` or the Prisma extension's
   `encryptWriteArgs` - the decorator alone does nothing without one of
   these.
3. If the field is nested more than 5 levels deep in the object graph or
   Prisma write payload, pass a larger `maxDepth` explicitly - the default
   throws rather than silently skipping it.
4. If the field is read back through an HTTP response, add
   `@TransformResponseTo(ResponseDto)` to the route handler.
5. Write a round-trip test: encrypt, then decrypt, and assert the original
   value comes back - this is the cheapest way to catch a depth or registry
   mismatch.

## Known gaps

- **No key rotation.** Rotating a tenant's DEK requires re-encrypting every
  existing ciphertext under the new key; this library has no built-in
  migration tooling for that.
- **No authenticated encryption.** AES-256-CBC provides confidentiality but
  not integrity - a corrupted or tampered ciphertext may decrypt to garbage
  rather than fail loudly. If your threat model requires tamper detection,
  wrap ciphertext in your own MAC or move to an AEAD mode.
- **A compromised KMS key or database is out of scope.** This library
  protects data at rest against someone with database access but not KMS
  access, and vice versa - it does not protect against an attacker with
  both.
