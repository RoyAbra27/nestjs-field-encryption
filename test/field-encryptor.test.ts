import 'reflect-metadata';
import * as crypto from 'crypto';
import { Encrypt } from '../src/decorators/encrypt.decorator';
import { FieldEncryptor } from '../src/field-encryptor';
import { EncryptionKeyProvider } from '../src/key-provider';
import { encryptWithDek } from '../src/dek-cipher';

class Contact {
  @Encrypt()
  ssn: string;

  publicNote: string;
}

class Company {
  @Encrypt()
  taxId: string;

  contact: Contact;
}

function fakeKeyProvider(): EncryptionKeyProvider & { calls: number } {
  const dek = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8').subarray(0, 32);
  return {
    calls: 0,
    async getDataKey() {
      this.calls++;
      return dek;
    },
  };
}

describe('FieldEncryptor', () => {
  it('encrypts only @Encrypt()-tagged fields, leaving others untouched', async () => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const contact = Object.assign(new Contact(), { ssn: '123-45-6789', publicNote: 'hello' });

    await encryptor.encryptTagged(contact, 'tenant-1');

    expect(contact.ssn).not.toEqual('123-45-6789');
    expect(contact.publicNote).toEqual('hello');
  });

  it('recurses into nested tagged objects', async () => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const company = Object.assign(new Company(), {
      taxId: 'TAX-1',
      contact: Object.assign(new Contact(), { ssn: '999-00-1111', publicNote: 'x' }),
    });

    await encryptor.encryptTagged(company, 'tenant-1');

    expect(company.taxId).not.toEqual('TAX-1');
    expect(company.contact.ssn).not.toEqual('999-00-1111');
  });

  it('fetches the DEK only once per encryptTagged call, even with multiple tagged fields', async () => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const company = Object.assign(new Company(), {
      taxId: 'TAX-1',
      contact: Object.assign(new Contact(), { ssn: '999-00-1111', publicNote: 'x' }),
    });

    await encryptor.encryptTagged(company, 'tenant-1');

    expect(keyProvider.calls).toBe(1);
  });

  it('is idempotent: re-encrypting an already-encrypted field is a no-op', async () => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const contact = Object.assign(new Contact(), { ssn: '123-45-6789', publicNote: 'hello' });

    await encryptor.encryptTagged(contact, 'tenant-1');
    const onceEncrypted = contact.ssn;
    await encryptor.encryptTagged(contact, 'tenant-1');

    expect(contact.ssn).toEqual(onceEncrypted);
  });

  it('round-trips through decryptTagged', async () => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const contact = Object.assign(new Contact(), { ssn: '123-45-6789', publicNote: 'hello' });

    await encryptor.encryptTagged(contact, 'tenant-1');
    await encryptor.decryptTagged(contact, 'tenant-1');

    expect(contact.ssn).toEqual('123-45-6789');
    expect(contact.publicNote).toEqual('hello');
  });

  it('throws when a tagged field is found deeper than maxDepth', async () => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const company = Object.assign(new Company(), {
      taxId: 'TAX-1',
      contact: Object.assign(new Contact(), { ssn: '999-00-1111', publicNote: 'x' }),
    });

    await expect(encryptor.encryptTagged(company, 'tenant-1', 0)).rejects.toThrow(/exceeds maxDepth/);
  });

  // --- // decryptTagged robustness (bug #1) // ---

  it.each([
    ['an empty-string tagged field', ''],
    ['a legacy plaintext value written before encryption', '123-45-6789'],
    ['a value encrypted under a different (rotated) key', encryptWithDek('secret', crypto.randomBytes(32))],
  ])('decryptTagged tolerates %s without throwing, leaving it untouched', async (_label, value) => {
    const keyProvider = fakeKeyProvider();
    const encryptor = new FieldEncryptor(keyProvider);
    const contact = Object.assign(new Contact(), { ssn: value, publicNote: 'hello' });

    await expect(encryptor.decryptTagged(contact, 'tenant-1')).resolves.toBeUndefined();
    expect(contact.ssn).toEqual(value);
    expect(contact.publicNote).toEqual('hello');
  });
});
