import { ArgumentMetadata, BadRequestException, Inject, Injectable, PipeTransform } from '@nestjs/common';
import { plainToClass } from 'class-transformer';
import { validate } from 'class-validator';
import { FieldEncryptor } from '../field-encryptor';
import { TENANT_ID_RESOLVER, TenantIdResolver } from '../tenant-id-resolver';

@Injectable()
export class EncryptPipe implements PipeTransform {
  constructor(
    private readonly fieldEncryptor: FieldEncryptor,
    @Inject(TENANT_ID_RESOLVER) private readonly resolveTenantId: TenantIdResolver,
  ) {}

  async transform(value: any, metadata: ArgumentMetadata) {
    if (!metadata.metatype) return value;

    const tenantId = this.resolveTenantId();
    const object = plainToClass(metadata.metatype, value);
    const errors = await validate(object);
    if (errors.length > 0) {
      throw new BadRequestException('Validation failed');
    }

    await this.fieldEncryptor.encryptTagged(object, tenantId);
    return object;
  }
}
