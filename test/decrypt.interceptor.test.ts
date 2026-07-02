import 'reflect-metadata';
import { of } from 'rxjs';
import { DecryptInterceptor, RESPONSE_TRANSFORM_METADATA_KEY } from '../src/interceptor/decrypt.interceptor';
import { FieldEncryptor } from '../src/field-encryptor';

class ContactResponseDto {
  ssn: string;
  publicNote: string;
}

function makeContext(path: string, responseClass?: any) {
  return {
    switchToHttp: () => ({ getRequest: () => ({ path }) }),
    getHandler: () => ({}),
    getClass: () => ({}),
  } as any;
}

describe('DecryptInterceptor', () => {
  beforeEach(() => {
    jest.spyOn(Reflect, 'getMetadata').mockImplementation((key) =>
      key === RESPONSE_TRANSFORM_METADATA_KEY ? ContactResponseDto : undefined,
    );
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('decrypts tagged fields on the response when a transform class is set', async () => {
    const fieldEncryptor = { decryptTagged: jest.fn() } as unknown as FieldEncryptor;
    const interceptor = new DecryptInterceptor(fieldEncryptor, () => 'tenant-1');
    const context = makeContext('/contacts/1');
    const next = { handle: () => of({ ssn: 'enc', publicNote: 'hi' }) };

    const result = await interceptor.intercept(context, next).toPromise().then((p) => p);
    const resolved = await result;

    expect(fieldEncryptor.decryptTagged).toHaveBeenCalledWith(resolved, 'tenant-1');
  });

  it('skips excluded routes entirely', async () => {
    const fieldEncryptor = { decryptTagged: jest.fn() } as unknown as FieldEncryptor;
    const interceptor = new DecryptInterceptor(fieldEncryptor, () => 'tenant-1', (path) => path === '/health');
    const context = makeContext('/health');
    const next = { handle: () => of({ ssn: 'enc' }) };

    const result = await interceptor.intercept(context, next).toPromise();

    expect(result).toEqual({ ssn: 'enc' });
    expect(fieldEncryptor.decryptTagged).not.toHaveBeenCalled();
  });

  it('passes through untouched when tenant resolution throws', async () => {
    const fieldEncryptor = { decryptTagged: jest.fn() } as unknown as FieldEncryptor;
    const interceptor = new DecryptInterceptor(fieldEncryptor, () => {
      throw new Error('no tenant on this request');
    });
    const context = makeContext('/public');
    const next = { handle: () => of({ ssn: 'enc' }) };

    const result = await interceptor.intercept(context, next).toPromise();

    expect(result).toEqual({ ssn: 'enc' });
    expect(fieldEncryptor.decryptTagged).not.toHaveBeenCalled();
  });
});
