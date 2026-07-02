import { DecryptCommand, KMSClient } from '@aws-sdk/client-kms';
import { DEK_ALGORITHM, DEK_KEY_LENGTH } from './dek-cipher';
import { EncryptionKeyProvider } from './key-provider';

export interface EncryptedKeyStore {
  getEncryptedDataKey(tenantId: string | number): Promise<string | null>;
}

export interface EncryptionCache {
  get(key: string): Promise<string | undefined>;
  set(key: string, value: string, ttlMs: number): Promise<void>;
}

export interface KmsKeyProviderOptions {
  /** AWS region; required unless `kmsClient` is supplied directly. */
  region?: string;
  /** Pre-constructed client, mainly for tests. */
  kmsClient?: KMSClient;
  /** Prefix + tenantId forms the KMS key alias, e.g. "alias/KEK-tenant-1". */
  keyAliasPrefix?: string;
  cache?: EncryptionCache;
  cacheTtlMs?: number;
}

const DEFAULT_KEY_ALIAS_PREFIX = 'alias/KEK-';
const DEFAULT_CACHE_TTL_MS = 1000 * 60 * 10;

/**
 * Envelope encryption: each tenant has a data-encryption key (DEK) stored
 * encrypted-at-rest by the caller (via `EncryptedKeyStore`) and unwrapped
 * on demand through a per-tenant AWS KMS key-encryption key (KEK).
 */
export class KmsKeyProvider implements EncryptionKeyProvider {
  private readonly kmsClient: KMSClient;

  constructor(
    private readonly keyStore: EncryptedKeyStore,
    private readonly options: KmsKeyProviderOptions = {},
  ) {
    if (!options.kmsClient && !options.region) {
      throw new Error('KmsKeyProvider requires either options.kmsClient or options.region');
    }
    this.kmsClient = options.kmsClient ?? new KMSClient({ region: options.region });
  }

  async getDataKey(tenantId: string | number, options?: { skipCache?: boolean }): Promise<Buffer> {
    const cacheKey = `dek:${tenantId}`;
    const skipCache = options?.skipCache === true;

    if (!skipCache && this.options.cache) {
      const cached = await this.options.cache.get(cacheKey);
      if (cached) return Buffer.from(cached, 'base64');
    }

    const encryptedDek = await this.keyStore.getEncryptedDataKey(tenantId);
    if (!encryptedDek) {
      throw new Error(`No encrypted data key found for tenant ${tenantId}`);
    }

    const alias = `${this.options.keyAliasPrefix ?? DEFAULT_KEY_ALIAS_PREFIX}${tenantId}`;
    const result = await this.kmsClient.send(
      new DecryptCommand({
        CiphertextBlob: Buffer.from(encryptedDek, 'base64') as Uint8Array,
        KeyId: alias,
      }),
    );

    if (!result.Plaintext) {
      throw new Error(`KMS returned no plaintext for tenant ${tenantId}`);
    }
    const dek = Buffer.from(result.Plaintext as Uint8Array);
    if (dek.length !== DEK_KEY_LENGTH) {
      throw new Error(
        `KMS returned a ${dek.length}-byte data key for tenant ${tenantId}; expected ${DEK_KEY_LENGTH} bytes for ${DEK_ALGORITHM}`,
      );
    }

    if (!skipCache && this.options.cache) {
      await this.options.cache.set(cacheKey, dek.toString('base64'), this.options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS);
    }

    return dek;
  }
}
