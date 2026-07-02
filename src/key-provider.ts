export interface EncryptionKeyProvider {
  getDataKey(tenantId: string | number, options?: { skipCache?: boolean }): Promise<Buffer>;
}
