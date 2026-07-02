import * as crypto from 'crypto';
import { encryptWithDek } from '../src/dek-cipher';
import { createFieldEncryptionExtension } from '../src/prisma-extension';

const dek = crypto.randomBytes(32);

const registry = {
  customer: ['taxId', 'billingEmail'],
  order: ['internalNotes'],
} as const;

const relationMap = {
  account: { customers: 'customer', orders: 'order' },
};

describe('createFieldEncryptionExtension', () => {
  it('encrypts registered columns on a direct create write', () => {
    const { encryptWriteArgs } = createFieldEncryptionExtension(registry);
    const args = { data: { taxId: 'TAX-1', billingEmail: 'a@b.com', name: 'Acme' } };

    encryptWriteArgs('customer', 'create', args, dek);

    expect(args.data.taxId).not.toEqual('TAX-1');
    expect(args.data.billingEmail).not.toEqual('a@b.com');
    expect(args.data.name).toEqual('Acme');
  });

  it('is idempotent: does not double-encrypt an already-encrypted column', () => {
    const { encryptWriteArgs } = createFieldEncryptionExtension(registry);
    const args = { data: { taxId: encryptWithDek('TAX-1', dek) } };
    const before = args.data.taxId;

    encryptWriteArgs('customer', 'update', args, dek);

    expect(args.data.taxId).toEqual(before);
  });

  it('encrypts registered columns on nested relation writes via the relation map', () => {
    const { encryptWriteArgs } = createFieldEncryptionExtension(registry, relationMap);
    const args = {
      data: {
        name: 'Acme Holdings',
        customers: { create: [{ taxId: 'TAX-2', billingEmail: 'x@y.com' }] },
      },
    };

    encryptWriteArgs('account', 'create', args, dek);

    expect(args.data.customers.create[0].taxId).not.toEqual('TAX-2');
  });

  it('handles upsert by encrypting both the create and update branches', () => {
    const { encryptWriteArgs } = createFieldEncryptionExtension(registry);
    const args = {
      create: { taxId: 'TAX-3', billingEmail: 'c@d.com' },
      update: { taxId: 'TAX-4' },
    };

    encryptWriteArgs('customer', 'upsert', args, dek);

    expect(args.create.taxId).not.toEqual('TAX-3');
    expect(args.update.taxId).not.toEqual('TAX-4');
  });

  it('detects unencrypted tagged columns without a DEK', () => {
    const { detectPlaintextTaggedColumns } = createFieldEncryptionExtension(registry);
    const args = { data: { taxId: 'TAX-5', billingEmail: encryptWithDek('already-enc', dek) } };

    const found = detectPlaintextTaggedColumns('customer', 'update', args);

    expect(found).toEqual(['taxId']);
  });

  it('processTaggedWrite encrypts when given a DEK, or reports plaintext columns when not', () => {
    const { processTaggedWrite } = createFieldEncryptionExtension(registry);
    const argsWithDek = { data: { taxId: 'TAX-6' } };
    const argsWithoutDek = { data: { taxId: 'TAX-7' } };

    const withDek = processTaggedWrite('customer', 'update', argsWithDek, dek.toString('base64'));
    const withoutDek = processTaggedWrite('customer', 'update', argsWithoutDek, undefined);

    expect(withDek.unencryptedColumns).toEqual([]);
    expect(argsWithDek.data.taxId).not.toEqual('TAX-6');
    expect(withoutDek.unencryptedColumns).toEqual(['taxId']);
    expect(argsWithoutDek.data.taxId).toEqual('TAX-7');
  });

  // --- // over-depth guard (bug #3) // ---

  const deepRegistry = { node: ['secret'] } as const;
  const deepRelationMap = { node: { child: 'node' } };
  const deeplyNestedArgs = () => ({
    data: {
      secret: 'level-0',
      child: { create: { secret: 'level-1', child: { create: { secret: 'level-2' } } } },
    },
  });

  it('throws instead of silently persisting a registered column nested beyond maxDepth', () => {
    const { encryptWriteArgs } = createFieldEncryptionExtension(deepRegistry, deepRelationMap, 1);
    const args = deeplyNestedArgs();

    expect(() => encryptWriteArgs('node', 'create', args, dek)).toThrow(/exceeds maxDepth/);
  });

  it('detectPlaintextTaggedColumns also throws for a column nested beyond maxDepth', () => {
    const { detectPlaintextTaggedColumns } = createFieldEncryptionExtension(deepRegistry, deepRelationMap, 1);

    expect(() => detectPlaintextTaggedColumns('node', 'create', deeplyNestedArgs())).toThrow(/exceeds maxDepth/);
  });

  it('does not throw when nesting stays within maxDepth', () => {
    const { encryptWriteArgs } = createFieldEncryptionExtension(deepRegistry, deepRelationMap, 5);
    const args = deeplyNestedArgs();

    expect(() => encryptWriteArgs('node', 'create', args, dek)).not.toThrow();
    expect(args.data.child.create.child.create.secret).not.toEqual('level-2');
  });
});
