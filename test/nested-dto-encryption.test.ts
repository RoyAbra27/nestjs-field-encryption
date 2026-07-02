import 'reflect-metadata';
import { plainToInstance, Type } from 'class-transformer';
import { Encrypt } from '../src/decorators/encrypt.decorator';
import { FieldEncryptor } from '../src/field-encryptor';
import { EncryptionKeyProvider } from '../src/key-provider';

function fakeKeyProvider(): EncryptionKeyProvider {
  const dek = Buffer.from('0123456789abcdef0123456789abcdef', 'utf8').subarray(0, 32);
  return { async getDataKey() { return dek; } };
}

class Address {
  @Encrypt()
  postalCode: string;
}

class CreatePersonWithType {
  name: string;

  @Type(() => Address)
  address: Address;
}

class CreatePersonWithoutType {
  name: string;

  address: Address;
}

// FieldEncryptor reads @Encrypt() metadata off the class prototype, so a nested
// value only gets encrypted when it is a real class instance. class-transformer
// only instantiates nested objects when the property carries @Type(); without it
// the nested object stays a plain object and its tagged fields are NOT seen.
describe('nested DTO encryption requires class-transformer @Type()', () => {
  it('encrypts a nested tagged field when the nested property uses @Type()', async () => {
    const encryptor = new FieldEncryptor(fakeKeyProvider());
    const dto = plainToInstance(CreatePersonWithType, { name: 'Ada', address: { postalCode: 'SW1A' } });

    await encryptor.encryptTagged(dto, 'tenant-1');

    expect(dto.address).toBeInstanceOf(Address);
    expect(dto.address.postalCode).not.toEqual('SW1A');
  });

  it('leaves a nested tagged field as plaintext when @Type() is missing (documented limitation)', async () => {
    const encryptor = new FieldEncryptor(fakeKeyProvider());
    const dto = plainToInstance(CreatePersonWithoutType, { name: 'Ada', address: { postalCode: 'SW1A' } });

    await encryptor.encryptTagged(dto, 'tenant-1');

    expect(dto.address).not.toBeInstanceOf(Address);
    expect(dto.address.postalCode).toEqual('SW1A');
  });
});
