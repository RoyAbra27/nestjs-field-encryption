import 'reflect-metadata';
import { BadRequestException } from '@nestjs/common';
import { IsString, MinLength } from 'class-validator';
import { Encrypt } from '../src/decorators/encrypt.decorator';
import { EncryptPipe } from '../src/pipe/encrypt.pipe';
import { FieldEncryptor } from '../src/field-encryptor';

class CreateContactDto {
  @IsString()
  @MinLength(1)
  publicNote: string;

  @Encrypt()
  @IsString()
  ssn: string;
}

describe('EncryptPipe', () => {
  it('validates, then encrypts tagged fields before returning the object', async () => {
    const fieldEncryptor = { encryptTagged: jest.fn() } as unknown as FieldEncryptor;
    const pipe = new EncryptPipe(fieldEncryptor, () => 'tenant-1');

    const result = await pipe.transform(
      { publicNote: 'hi', ssn: '123-45-6789' },
      { metatype: CreateContactDto, type: 'body' } as any,
    );

    expect(result).toBeInstanceOf(CreateContactDto);
    expect(fieldEncryptor.encryptTagged).toHaveBeenCalledWith(result, 'tenant-1');
  });

  it('throws BadRequestException on validation failure', async () => {
    const fieldEncryptor = { encryptTagged: jest.fn() } as unknown as FieldEncryptor;
    const pipe = new EncryptPipe(fieldEncryptor, () => 'tenant-1');

    await expect(
      pipe.transform({ publicNote: '', ssn: '123' }, { metatype: CreateContactDto, type: 'body' } as any),
    ).rejects.toThrow(BadRequestException);
    expect(fieldEncryptor.encryptTagged).not.toHaveBeenCalled();
  });

  it('passes values through untouched when there is no DTO metatype', async () => {
    const fieldEncryptor = { encryptTagged: jest.fn() } as unknown as FieldEncryptor;
    const pipe = new EncryptPipe(fieldEncryptor, () => 'tenant-1');

    const result = await pipe.transform('raw', { metatype: undefined, type: 'param' } as any);

    expect(result).toEqual('raw');
    expect(fieldEncryptor.encryptTagged).not.toHaveBeenCalled();
  });
});
