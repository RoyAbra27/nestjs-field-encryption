import * as crypto from 'crypto';

export const DEK_ALGORITHM = 'aes-256-cbc';
export const DEK_IV_LENGTH = 16;

const CANONICAL_BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

export function encryptWithDek(data: unknown, dek: Buffer): string {
  const stringToEncrypt = JSON.stringify(data);
  const iv = crypto.randomBytes(DEK_IV_LENGTH) as Uint8Array;

  const cipher = crypto.createCipheriv(DEK_ALGORITHM, dek as unknown as Uint8Array, iv);
  const updateResult = cipher.update(stringToEncrypt, 'utf8') as Uint8Array;
  const finalResult = cipher.final() as Uint8Array;
  const encrypted = Buffer.concat([updateResult, finalResult]) as Uint8Array;
  return Buffer.concat([iv, encrypted]).toString('base64');
}

/**
 * True only when `value` decrypts cleanly under `dek` AND the plaintext parses
 * as JSON. `encryptWithDek` always JSON.stringifies, so every genuine ciphertext
 * is valid JSON; requiring that rejects arbitrary data whose CBC decrypt happens
 * to yield valid PKCS#7 padding by chance (~1/256), which would otherwise be
 * mistaken for an already-encrypted value and left as plaintext. Relies on one
 * DEK per tenant (no rotation): a clean JSON decrypt means the value is ours.
 */
export function isEncryptedWithDek(value: string, dek: Buffer): boolean {
  try {
    const buf = Buffer.from(value, 'base64');
    if (buf.length < DEK_IV_LENGTH * 2) return false;
    const iv = buf.subarray(0, DEK_IV_LENGTH) as Uint8Array;
    const encryptedText = buf.subarray(DEK_IV_LENGTH) as Uint8Array;
    const decipher = crypto.createDecipheriv(DEK_ALGORITHM, dek as unknown as Uint8Array, iv);
    const decrypted = Buffer.concat([
      decipher.update(encryptedText) as Uint8Array,
      decipher.final() as Uint8Array,
    ]);
    JSON.parse(decrypted.toString());
    return true;
  } catch {
    return false;
  }
}

/**
 * DEK-free shape check used where no DEK is in scope: an AES-256-CBC payload is
 * base64(IV(16) || n×16-byte blocks), so it decodes to >=32 bytes that are a
 * multiple of the block size. Plaintext almost never satisfies both.
 */
export function looksEncrypted(value: string): boolean {
  if (typeof value !== 'string' || value.length === 0) return false;
  if (value.length % 4 !== 0 || !CANONICAL_BASE64.test(value)) return false;
  const buf = Buffer.from(value, 'base64');
  return buf.length >= DEK_IV_LENGTH * 2 && buf.length % DEK_IV_LENGTH === 0;
}
