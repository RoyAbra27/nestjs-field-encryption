# nestjs-field-encryption

[![npm version](https://img.shields.io/npm/v/nestjs-field-encryption.svg)](https://www.npmjs.com/package/nestjs-field-encryption)
[![CI](https://github.com/RoyAbra27/nestjs-field-encryption/actions/workflows/ci.yml/badge.svg)](https://github.com/RoyAbra27/nestjs-field-encryption/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Per-tenant field-level encryption for NestJS: AES-256-CBC + KMS envelope
encryption, a `@Encrypt()` decorator, an HTTP pipe/interceptor pair for
automatic encrypt-on-write / decrypt-on-read, and a schema-agnostic Prisma
write-encryption extension.

## Why not roll your own?

Field-level encryption in a multi-tenant app looks simple until you actually
build it. A few ways to get it subtly wrong:

- **Forgetting idempotency** — re-encrypting an already-encrypted value (on a
  retried write, or a partial update) produces garbage instead of a no-op.
- **Forgetting a depth guard** — a naive recursive walk over nested DTOs or
  Prisma nested writes can silently skip a tagged field several levels down,
  writing plaintext to a column meant to be encrypted.
- **Mixing up IV reuse** — reusing an IV across encryptions under the same
  key breaks AES-CBC's confidentiality guarantees. Every encrypt call in this
  library generates a fresh random IV.

This library encodes those lessons so you don't have to relearn them.

## Install

```bash
npm install nestjs-field-encryption @aws-sdk/client-kms reflect-metadata
```

`@nestjs/common`, `class-transformer`, `class-validator`, and `rxjs` are peer
dependencies — install whichever versions your NestJS app already uses.

## Core concepts

- **`EncryptionKeyProvider`** — resolves a per-tenant data-encryption key
  (DEK). `KmsKeyProvider` implements this via AWS KMS envelope encryption:
  each tenant's DEK is stored encrypted-at-rest (via your own
  `EncryptedKeyStore`) and unwrapped on demand through a per-tenant KMS key.
- **`@Encrypt()`** — a property decorator that tags a DTO/entity field for
  encryption.
- **`FieldEncryptor`** — walks an object graph and encrypts/decrypts every
  `@Encrypt()`-tagged field, recursing into nested objects up to a
  configurable depth.
- **`EncryptPipe` / `DecryptInterceptor`** — wire `FieldEncryptor` into the
  NestJS request/response lifecycle automatically.
- **`createFieldEncryptionExtension`** — a schema-agnostic Prisma extension
  factory for encrypting columns directly at the database-write layer,
  independent of the HTTP pipe/interceptor.

## Worked example

```typescript
// encryption.module.ts
import { Module } from '@nestjs/common';
import { KmsKeyProvider, FieldEncryptor, TENANT_ID_RESOLVER } from 'nestjs-field-encryption';
import { RequestContext } from './request-context';
import { TenantKeyStore } from './tenant-key-store';

@Module({
  providers: [
    {
      provide: KmsKeyProvider,
      useFactory: (keyStore: TenantKeyStore) =>
        new KmsKeyProvider(keyStore, { region: 'us-east-1' }),
      inject: [TenantKeyStore],
    },
    {
      provide: FieldEncryptor,
      useFactory: (keyProvider: KmsKeyProvider) => new FieldEncryptor(keyProvider),
      inject: [KmsKeyProvider],
    },
    {
      provide: TENANT_ID_RESOLVER,
      useFactory: (ctx: RequestContext) => () => ctx.getTenantId(),
      inject: [RequestContext],
    },
  ],
  exports: [FieldEncryptor, TENANT_ID_RESOLVER],
})
export class EncryptionModule {}
```

```typescript
// create-customer.dto.ts
import { IsEmail, IsString } from 'class-validator';
import { Encrypt } from 'nestjs-field-encryption';

export class CreateCustomerDto {
  @IsString()
  name: string;

  @Encrypt()
  @IsString()
  taxId: string;
}
```

```typescript
// customers.controller.ts
import { Body, Controller, Get, Param, Post, UsePipes, UseInterceptors } from '@nestjs/common';
import { EncryptPipe, DecryptInterceptor, TransformResponseTo } from 'nestjs-field-encryption';
import { CreateCustomerDto } from './create-customer.dto';
import { CustomerResponseDto } from './customer-response.dto';

@Controller('customers')
@UseInterceptors(DecryptInterceptor)
export class CustomersController {
  @Post()
  @UsePipes(EncryptPipe)
  create(@Body() dto: CreateCustomerDto) {
    // dto.taxId is already encrypted by the time it reaches this handler
    return this.customersService.create(dto);
  }

  @Get(':id')
  @TransformResponseTo(CustomerResponseDto)
  findOne(@Param('id') id: string) {
    // the interceptor decrypts tagged fields on CustomerResponseDto before it's sent
    return this.customersService.findOne(id);
  }
}
```

## Prisma write-encryption extension

For encrypting columns at the database-write layer instead of (or alongside)
the HTTP pipe, use `createFieldEncryptionExtension` with a registry mapping
model names to their encrypted columns:

```typescript
import { createFieldEncryptionExtension } from 'nestjs-field-encryption';

const registry = {
  customer: ['taxId', 'billingEmail'],
  order: ['internalNotes'],
} as const;

// Nested writes (e.g. account.create({ data: { customers: { create: [...] } } }))
// are covered by an optional relation map:
const relationMap = {
  account: { customers: 'customer', orders: 'order' },
};

const { encryptWriteArgs, processTaggedWrite } = createFieldEncryptionExtension(registry, relationMap);

// Call encryptWriteArgs(model, operation, args, dek) from a Prisma $extends
// query hook before the write hits the database.
```

`processTaggedWrite` is a convenience wrapper: pass a DEK to encrypt in
place, or omit it to get back a list of tagged columns that are still
plaintext (useful for a pre-write assertion that nothing unencrypted reaches
the database).

## Further reading

- [docs/architecture.md](docs/architecture.md) — primitives, write/read
  contracts, key management, failure handling, and a checklist for adding a
  new encrypted field.
- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
