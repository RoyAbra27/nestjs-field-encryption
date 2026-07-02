import * as crypto from 'crypto';
import { DEK_ALGORITHM, DEK_IV_LENGTH, encryptWithDek, isEncryptedWithDek } from './dek-cipher';
import { EncryptionKeyProvider } from './key-provider';

export const ENCRYPT_MAX_DEPTH = 5;

type GetDek = () => Promise<Buffer>;

export class FieldEncryptor {
  constructor(private readonly keyProvider: EncryptionKeyProvider) {}

  decryptValue(encryptedData: string, dek: Buffer): unknown {
    let decrypted: Buffer;
    try {
      const ivAndEncrypted = Buffer.from(encryptedData, 'base64');
      const iv = ivAndEncrypted.subarray(0, DEK_IV_LENGTH) as Uint8Array;
      const encryptedText = ivAndEncrypted.subarray(DEK_IV_LENGTH) as Uint8Array;
      const decipher = crypto.createDecipheriv(DEK_ALGORITHM, dek as unknown as Uint8Array, iv);
      decrypted = Buffer.concat([
        decipher.update(encryptedText) as Uint8Array,
        decipher.final() as Uint8Array,
      ]);
    } catch {
      // Not decryptable under this DEK: an empty/legacy-plaintext value, or one
      // written under a different key. Return it untouched rather than throwing,
      // which would 500 the whole response. Mirrors encryptTaggedField's
      // isEncryptedWithDek idempotency guard on the write side.
      return encryptedData;
    }
    try {
      return JSON.parse(decrypted.toString());
    } catch {
      return decrypted.toString();
    }
  }

  /**
   * Recursively encrypts every `@Encrypt()`-tagged field on `obj`. The DEK is
   * fetched lazily and memoized for the whole call, so an object with several
   * tagged fields only hits the key provider once.
   */
  async encryptTagged(obj: any, tenantId: string | number, maxDepth = ENCRYPT_MAX_DEPTH): Promise<void> {
    this.assertNoTaggedFieldsBeyondMaxDepth(obj, maxDepth);
    let dekPromise: Promise<Buffer> | null = null;
    const getDek: GetDek = () => (dekPromise ??= this.keyProvider.getDataKey(tenantId));
    await this.walkAndEncrypt(obj, getDek, 0, maxDepth);
  }

  async decryptTagged(obj: any, tenantId: string | number, maxDepth = ENCRYPT_MAX_DEPTH): Promise<void> {
    this.assertNoTaggedFieldsBeyondMaxDepth(obj, maxDepth);
    let dekPromise: Promise<Buffer> | null = null;
    const getDek: GetDek = () => (dekPromise ??= this.keyProvider.getDataKey(tenantId));
    await this.walkAndDecrypt(obj, getDek, 0, maxDepth);
  }

  // Runs once up front so a tagged field beyond maxDepth throws instead of
  // being silently skipped by the walk -- which would write plaintext on
  // encrypt, or return ciphertext to the caller on decrypt.
  private assertNoTaggedFieldsBeyondMaxDepth(obj: any, maxDepth: number): void {
    const walk = (node: any, depth: number) => {
      if (Array.isArray(node)) {
        for (const item of node) walk(item, depth + 1);
        return;
      }
      if (!node || typeof node !== 'object') return;
      for (const key of Object.keys(node)) {
        const tagged = Reflect.getMetadata('encrypt', node, key);
        if (depth > maxDepth && tagged) {
          throw new Error(
            `FieldEncryptor: tagged field "${key}" found at depth ${depth} which exceeds maxDepth (${maxDepth})`,
          );
        }
        // A tagged field is encrypted whole (as one value), so its subtree is
        // never walked individually; don't descend into it here either, or a
        // deeper tag inside it would falsely trip the guard.
        if (!tagged && node[key] && typeof node[key] === 'object') walk(node[key], depth + 1);
      }
    };
    walk(obj, 0);
  }

  private async walkAndEncrypt(obj: any, getDek: GetDek, depth: number, maxDepth: number): Promise<void> {
    if (depth > maxDepth) return;
    if (Array.isArray(obj)) {
      await Promise.all(obj.map((item) => this.walkAndEncrypt(item, getDek, depth + 1, maxDepth)));
      return;
    }
    if (obj && typeof obj === 'object') {
      await Promise.all(
        Object.keys(obj).map(async (key) => {
          if (obj[key] && typeof obj[key] === 'object' && obj[key] !== null) {
            if (Reflect.getMetadata('encrypt', obj, key)) {
              obj[key] = await this.encryptTaggedField(obj, key, getDek);
            }
            await this.walkAndEncrypt(obj[key], getDek, depth + 1, maxDepth);
          } else if (Reflect.getMetadata('encrypt', obj, key) && obj[key] !== null) {
            obj[key] = await this.encryptTaggedField(obj, key, getDek);
          }
        }),
      );
    }
  }

  private async encryptTaggedField(obj: any, key: string, getDek: GetDek): Promise<any> {
    if (obj[key] === null || obj[key] === undefined) return null;
    const dek = await getDek();
    // Idempotent: skip values already encrypted under this DEK.
    if (typeof obj[key] === 'string' && isEncryptedWithDek(obj[key], dek)) {
      return obj[key];
    }
    return encryptWithDek(obj[key], dek);
  }

  private async walkAndDecrypt(obj: any, getDek: GetDek, depth: number, maxDepth: number): Promise<void> {
    if (depth > maxDepth) return;
    if (Array.isArray(obj)) {
      await Promise.all(obj.map((item) => this.walkAndDecrypt(item, getDek, depth + 1, maxDepth)));
      return;
    }
    if (obj && typeof obj === 'object') {
      await Promise.all(
        Object.entries(obj).map(async ([key, value]) => {
          if (Reflect.getMetadata('encrypt', obj, key) && value !== null) {
            const dek = await getDek();
            (obj as any)[key] = this.decryptValue(value as string, dek);
          } else if (value && typeof value === 'object') {
            await this.walkAndDecrypt(value, getDek, depth + 1, maxDepth);
          }
        }),
      );
    }
  }
}
