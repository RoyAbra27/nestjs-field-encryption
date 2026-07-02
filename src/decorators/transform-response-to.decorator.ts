import { SetMetadata } from '@nestjs/common';
import { RESPONSE_TRANSFORM_METADATA_KEY } from '../interceptor/decrypt.interceptor';

export const TransformResponseTo = (responseClass: new (...args: any[]) => any) =>
  SetMetadata(RESPONSE_TRANSFORM_METADATA_KEY, responseClass);
