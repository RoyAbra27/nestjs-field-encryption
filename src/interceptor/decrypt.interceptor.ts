import { CallHandler, ExecutionContext, Inject, Injectable, NestInterceptor, Optional } from '@nestjs/common';
import { plainToInstance } from 'class-transformer';
import { Observable } from 'rxjs';
import { map } from 'rxjs/operators';
import { FieldEncryptor } from '../field-encryptor';
import { TENANT_ID_RESOLVER, TenantIdResolver } from '../tenant-id-resolver';

export const RESPONSE_TRANSFORM_METADATA_KEY = 'transformResponseTo';

@Injectable()
export class DecryptInterceptor implements NestInterceptor {
  constructor(
    private readonly fieldEncryptor: FieldEncryptor,
    @Inject(TENANT_ID_RESOLVER) private readonly resolveTenantId: TenantIdResolver,
    @Optional() private readonly isExcludedRoute?: (path: string) => boolean,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const basePath = req?.path;

    if (!basePath || this.isExcludedRoute?.(basePath)) {
      return next.handle();
    }

    let tenantId: string | number;
    try {
      tenantId = this.resolveTenantId();
    } catch {
      return next.handle();
    }

    return next.handle().pipe(
      map(async (data) => {
        const responseClass = Reflect.getMetadata(RESPONSE_TRANSFORM_METADATA_KEY, context.getHandler());
        if (!responseClass) return data;

        data = plainToInstance(responseClass, data);
        if (!data || (typeof data !== 'object' && !Array.isArray(data))) return data;

        await this.fieldEncryptor.decryptTagged(data, tenantId);
        return data;
      }),
    );
  }
}
