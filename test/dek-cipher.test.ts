import * as crypto from 'crypto';
import {
  DEK_ALGORITHM,
  DEK_IV_LENGTH,
  encryptWithDek,
  decryptWithDek,
  isEncryptedWithDek,
  looksEncrypted,
} from '../src/dek-cipher';

const testDek = crypto.randomBytes(32);
const otherDek = crypto.randomBytes(32);

describe('encryptWithDek / isEncryptedWithDek round trip', () => {
  it('produces a value that decrypts back to the original data', () => {
    const encrypted = encryptWithDek({ hello: 'world' }, testDek);
    expect(isEncryptedWithDek(encrypted, testDek)).toBe(true);

    const iv = Buffer.from(encrypted, 'base64').subarray(0, DEK_IV_LENGTH);
    const decipher = crypto.createDecipheriv(DEK_ALGORITHM, testDek, iv);
    const encryptedText = Buffer.from(encrypted, 'base64').subarray(DEK_IV_LENGTH);
    const decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);
    expect(JSON.parse(decrypted.toString())).toEqual({ hello: 'world' });
  });

  it('rejects a value encrypted under a different key', () => {
    const encrypted = encryptWithDek('secret', testDek);
    expect(isEncryptedWithDek(encrypted, otherDek)).toBe(false);
  });

  it('produces a different ciphertext each time (random IV)', () => {
    const first = encryptWithDek('same input', testDek);
    const second = encryptWithDek('same input', testDek);
    expect(first).not.toEqual(second);
  });

  it('rejects plaintext strings shorter than two IV lengths', () => {
    expect(isEncryptedWithDek('short', testDek)).toBe(false);
  });

  it('rejects a value that decrypts cleanly but is not one of our JSON ciphertexts (bug #4)', () => {
    // A payload encrypted under the DEK without going through encryptWithDek's
    // JSON.stringify: it decrypts with valid padding but is not our format.
    // Stands in for the chance-valid-padding false positive that would cause a
    // genuine plaintext value to be treated as already-encrypted and skipped.
    const iv = crypto.randomBytes(DEK_IV_LENGTH);
    const cipher = crypto.createCipheriv(DEK_ALGORITHM, testDek, iv);
    const enc = Buffer.concat([cipher.update(Buffer.from('this is not json at all')), cipher.final()]);
    const nonJson = Buffer.concat([iv, enc]).toString('base64');

    expect(isEncryptedWithDek(nonJson, testDek)).toBe(false);
  });
});

describe('decryptWithDek', () => {
  it('is the inverse of encryptWithDek', () => {
    const encrypted = encryptWithDek({ hello: 'world', n: 42 }, testDek);
    expect(decryptWithDek(encrypted, testDek)).toEqual({ hello: 'world', n: 42 });
  });

  it('throws when the value was not encrypted under the given key', () => {
    const encrypted = encryptWithDek('secret', testDek);
    expect(() => decryptWithDek(encrypted, otherDek)).toThrow();
  });
});

describe('looksEncrypted', () => {
  it('returns true for canonical-base64 ciphertext-shaped values', () => {
    const encrypted = encryptWithDek('some value', testDek);
    expect(looksEncrypted(encrypted)).toBe(true);
  });

  it('returns false for plain text', () => {
    expect(looksEncrypted('Alice')).toBe(false);
  });

  it('returns false for an empty string', () => {
    expect(looksEncrypted('')).toBe(false);
  });

  it('returns false for base64 that is not a multiple of the block size', () => {
    expect(looksEncrypted(Buffer.from('short').toString('base64'))).toBe(false);
  });
});
