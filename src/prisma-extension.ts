import { encryptWithDek, isEncryptedWithDek, looksEncrypted } from './dek-cipher';

export type EncryptedWriteRegistry = Record<string, readonly string[]>;
export type NestedWriteRelationMap = Record<string, Record<string, string>>;

export const DEFAULT_NESTED_WRITE_MAX_DEPTH = 5;

export const ENCRYPTED_WRITE_OPERATIONS = ['create', 'update', 'upsert', 'createMany', 'updateMany'] as const;
export type EncryptedWriteOperation = (typeof ENCRYPTED_WRITE_OPERATIONS)[number];

type WriteArgs = Record<string, any>;

const isObject = (v: unknown): v is Record<string, any> => typeof v === 'object' && v !== null;

function dataRecordsFor(operation: EncryptedWriteOperation, args: WriteArgs | undefined): Record<string, any>[] {
  if (!isObject(args)) return [];
  if (operation === 'upsert') {
    return [args.create, args.update].filter(isObject);
  }
  if (operation === 'createMany') {
    if (Array.isArray(args.data)) return args.data.filter(isObject);
    return isObject(args.data) ? [args.data] : [];
  }
  return isObject(args.data) ? [args.data] : [];
}

function nestedChildRecords(relationValue: unknown): Record<string, any>[] {
  if (!isObject(relationValue)) return [];
  const records: Record<string, any>[] = [];

  const pushData = (node: unknown) => {
    if (!isObject(node)) return;
    if (isObject(node.data)) records.push(node.data);
    else records.push(node);
  };

  const create = relationValue.create;
  if (Array.isArray(create)) create.filter(isObject).forEach((r) => records.push(r));
  else if (isObject(create)) records.push(create);

  const createMany = relationValue.createMany;
  if (isObject(createMany)) {
    if (Array.isArray(createMany.data)) createMany.data.filter(isObject).forEach((r) => records.push(r));
    else if (isObject(createMany.data)) records.push(createMany.data);
  }

  const upsert = relationValue.upsert;
  const upserts = Array.isArray(upsert) ? upsert : [upsert];
  for (const u of upserts) {
    if (!isObject(u)) continue;
    if (isObject(u.create)) records.push(u.create);
    if (isObject(u.update)) records.push(u.update);
  }

  const update = relationValue.update;
  if (Array.isArray(update)) update.forEach(pushData);
  else pushData(update);

  const updateMany = relationValue.updateMany;
  if (Array.isArray(updateMany)) updateMany.forEach(pushData);
  else pushData(updateMany);

  return records;
}

function stringSlot(
  record: Record<string, any>,
  column: string,
): { value: string; assign: (v: string) => void } | null {
  const raw = record[column];
  if (typeof raw === 'string') {
    return { value: raw, assign: (v) => (record[column] = v) };
  }
  if (isObject(raw) && typeof raw.set === 'string') {
    return { value: raw.set, assign: (v) => (raw.set = v) };
  }
  return null;
}

export function createFieldEncryptionExtension(
  registry: EncryptedWriteRegistry,
  relationMap: NestedWriteRelationMap = {},
  maxDepth: number = DEFAULT_NESTED_WRITE_MAX_DEPTH,
) {
  const isEncryptedModel = (model: string): boolean => model in registry;
  const relationsFor = (model: string): Record<string, string> => relationMap[model] ?? {};

  function encryptRecordColumns(model: string, record: Record<string, any>, dek: Buffer): void {
    for (const column of registry[model] ?? []) {
      const slot = stringSlot(record, column);
      if (!slot) continue;
      if (isEncryptedWithDek(slot.value, dek)) continue;
      slot.assign(encryptWithDek(slot.value, dek));
    }
  }

  function encryptNested(model: string, record: Record<string, any>, dek: Buffer, depth: number): void {
    if (depth >= maxDepth) return;
    for (const [relation, childModel] of Object.entries(relationsFor(model))) {
      for (const child of nestedChildRecords(record[relation])) {
        encryptRecordColumns(childModel, child, dek);
        encryptNested(childModel, child, dek, depth + 1);
      }
    }
  }

  // Mirrors FieldEncryptor.assertNoTaggedFieldsBeyondMaxDepth: a registered
  // column nested deeper than maxDepth must throw rather than being silently
  // skipped (which would persist it as plaintext). Walks the finite write
  // payload, so no cap is needed to terminate.
  function assertRegisteredColumnsWithinDepth(model: string, record: Record<string, any>, level: number): void {
    for (const [relation, childModel] of Object.entries(relationsFor(model))) {
      for (const child of nestedChildRecords(record[relation])) {
        const childLevel = level + 1;
        if (childLevel > maxDepth) {
          for (const column of registry[childModel] ?? []) {
            if (stringSlot(child, column)) {
              throw new Error(
                `createFieldEncryptionExtension: registered column "${childModel}.${column}" is nested at depth ${childLevel} which exceeds maxDepth (${maxDepth}); increase maxDepth or flatten the write to avoid silently persisting it as plaintext`,
              );
            }
          }
        }
        assertRegisteredColumnsWithinDepth(childModel, child, childLevel);
      }
    }
  }

  function encryptWriteArgs(model: string, operation: EncryptedWriteOperation, args: WriteArgs, dek: Buffer): void {
    for (const record of dataRecordsFor(operation, args)) {
      assertRegisteredColumnsWithinDepth(model, record, 0);
      if (isEncryptedModel(model)) encryptRecordColumns(model, record, dek);
      encryptNested(model, record, dek, 0);
    }
  }

  function detectRecordColumns(
    model: string,
    record: Record<string, any>,
    prefix: string,
    found: Set<string>,
  ): void {
    for (const column of registry[model] ?? []) {
      const slot = stringSlot(record, column);
      if (slot && !looksEncrypted(slot.value)) found.add(`${prefix}${column}`);
    }
  }

  function detectNested(
    model: string,
    record: Record<string, any>,
    prefix: string,
    found: Set<string>,
    depth: number,
  ): void {
    if (depth >= maxDepth) return;
    for (const [relation, childModel] of Object.entries(relationsFor(model))) {
      for (const child of nestedChildRecords(record[relation])) {
        const childPrefix = `${prefix}${relation}.`;
        detectRecordColumns(childModel, child, childPrefix, found);
        detectNested(childModel, child, childPrefix, found, depth + 1);
      }
    }
  }

  function detectPlaintextTaggedColumns(model: string, operation: EncryptedWriteOperation, args: WriteArgs): string[] {
    const found = new Set<string>();
    for (const record of dataRecordsFor(operation, args)) {
      assertRegisteredColumnsWithinDepth(model, record, 0);
      if (isEncryptedModel(model)) detectRecordColumns(model, record, '', found);
      detectNested(model, record, '', found, 0);
    }
    return [...found];
  }

  function processTaggedWrite(
    model: string,
    operation: EncryptedWriteOperation,
    args: WriteArgs,
    dekBase64: string | undefined,
  ): { unencryptedColumns: string[] } {
    if (dekBase64) {
      encryptWriteArgs(model, operation, args, Buffer.from(dekBase64, 'base64'));
      return { unencryptedColumns: [] };
    }
    return { unencryptedColumns: detectPlaintextTaggedColumns(model, operation, args) };
  }

  return { encryptWriteArgs, detectPlaintextTaggedColumns, processTaggedWrite };
}
