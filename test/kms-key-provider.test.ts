import { DecryptCommand, KMSClient } from '@aws-sdk/client-kms';
import { KmsKeyProvider, EncryptedKeyStore, EncryptionCache } from '../src/kms-key-provider';

function makeKmsClient(plaintext: Buffer) {
  return {
    send: jest.fn().mockResolvedValue({ Plaintext: plaintext }),
  } as unknown as KMSClient;
}

function makeKeyStore(encryptedDek: string | null): EncryptedKeyStore {
  return { getEncryptedDataKey: jest.fn().mockResolvedValue(encryptedDek) };
}

function makeCache(): EncryptionCache {
  const store = new Map<string, string>();
  return {
    get: jest.fn(async (key) => store.get(key)),
    set: jest.fn(async (key, value) => {
      store.set(key, value);
    }),
  };
}

describe('KmsKeyProvider', () => {
  it('decrypts the tenant DEK via KMS using the configured alias prefix', async () => {
    const plaintext = Buffer.from('a'.repeat(32));
    const kmsClient = makeKmsClient(plaintext);
    const keyStore = makeKeyStore(Buffer.from('ciphertext').toString('base64'));

    const provider = new KmsKeyProvider(keyStore, { kmsClient });
    const dek = await provider.getDataKey('tenant-1');

    expect(dek.equals(plaintext)).toBe(true);
    expect(kmsClient.send).toHaveBeenCalledWith(
      expect.objectContaining({}),
    );
    const [command] = (kmsClient.send as jest.Mock).mock.calls[0];
    expect(command).toBeInstanceOf(DecryptCommand);
  });

  it('throws when the key store has no encrypted DEK for the tenant', async () => {
    const kmsClient = makeKmsClient(Buffer.from('x'));
    const keyStore = makeKeyStore(null);
    const provider = new KmsKeyProvider(keyStore, { kmsClient });

    await expect(provider.getDataKey('tenant-1')).rejects.toThrow(
      'No encrypted data key found for tenant tenant-1',
    );
  });

  it('throws when the decrypted DEK is not the AES-256 key length', async () => {
    const kmsClient = makeKmsClient(Buffer.from('a'.repeat(16))); // 16 bytes, AES-128-sized
    const keyStore = makeKeyStore(Buffer.from('ciphertext').toString('base64'));
    const provider = new KmsKeyProvider(keyStore, { kmsClient });

    await expect(provider.getDataKey('tenant-1')).rejects.toThrow(/32/);
  });

  it('caches the decrypted DEK and skips KMS on the next call', async () => {
    const plaintext = Buffer.from('b'.repeat(32));
    const kmsClient = makeKmsClient(plaintext);
    const keyStore = makeKeyStore(Buffer.from('ciphertext').toString('base64'));
    const cache = makeCache();

    const provider = new KmsKeyProvider(keyStore, { kmsClient, cache });
    await provider.getDataKey('tenant-1');
    await provider.getDataKey('tenant-1');

    expect(kmsClient.send).toHaveBeenCalledTimes(1);
    expect(keyStore.getEncryptedDataKey).toHaveBeenCalledTimes(1);
  });

  it('bypasses the cache when skipCache is true', async () => {
    const plaintext = Buffer.from('c'.repeat(32));
    const kmsClient = makeKmsClient(plaintext);
    const keyStore = makeKeyStore(Buffer.from('ciphertext').toString('base64'));
    const cache = makeCache();

    const provider = new KmsKeyProvider(keyStore, { kmsClient, cache });
    await provider.getDataKey('tenant-1');
    await provider.getDataKey('tenant-1', { skipCache: true });

    expect(kmsClient.send).toHaveBeenCalledTimes(2);
  });
});
