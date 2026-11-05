import { computeHash } from './crypto.js';

export interface D1PreparedStatementLike {
  bind(...values: unknown[]): D1PreparedStatementLike;
  first<T = unknown>(): Promise<T | null>;
  run(): Promise<{ meta: { changes: number; last_row_id: number } }>;
}

export interface D1DatabaseLike {
  prepare(query: string): D1PreparedStatementLike;
}

export interface AuditEnvLike {
  DB?: D1DatabaseLike;
}

export interface AuditExecutionContextLike {
  get(key: 'user'): { id?: number } | undefined;
  env: AuditEnvLike;
  executionCtx?: {
    waitUntil?(promise: Promise<unknown>): void;
  };
}

export type AuditLogHashRecord = {
  user_id: number;
  facility_id: number;
  action: string;
  target_table?: string | null;
  target_id?: number | null;
  old_value?: string | null;
  new_value?: string | null;
  previous_hash?: string | null;
  current_hash?: string | null;
};

export const buildAuditLogHashInput = (record: AuditLogHashRecord): string => {
  const previousHash = record.previous_hash ?? 'genesis';
  const targetTable = record.target_table ?? 'undefined';
  const targetId = record.target_id ?? 'undefined';
  const oldValue = record.old_value ?? '';
  const newValue = record.new_value ?? '';

  return `${previousHash}|${record.user_id}|${record.action}|${targetTable}|${targetId}|${oldValue}|${newValue}`;
};

export const computeAuditLogCurrentHash = (record: AuditLogHashRecord): Promise<string> =>
  computeHash(buildAuditLogHashInput(record));

export type AuditLogWriteParams = {
  facilityId: number;
  action: string;
  targetTable: string;
  targetId?: number;
  oldValue?: unknown;
  newValue?: unknown;
  valuesAreSerialized?: boolean;
};

export type AuditLogWriteResult = {
  id: number;
  created_at: string;
  current_hash: string;
};

const serializeAuditValue = (value: unknown, valuesAreSerialized: boolean): string => {
  if (value === undefined) return '';
  if (valuesAreSerialized && typeof value === 'string') return value;
  return JSON.stringify(value);
};

/**
 * Appends an audit log through an optimistic compare-and-set (CAS) query
 * against the tenant/facility's current chain head on Cloudflare D1 / SQLite.
 */
export async function appendAuditLog(
  env: AuditEnvLike,
  userId: number,
  params: AuditLogWriteParams
): Promise<AuditLogWriteResult> {
  if (!env.DB || typeof env.DB.prepare !== 'function') {
    throw new Error('D1 database binding is required for audit logging.');
  }

  const oldValStr = serializeAuditValue(params.oldValue, params.valuesAreSerialized === true);
  const newValStr = serializeAuditValue(params.newValue, params.valuesAreSerialized === true);

  const appendStatement =
    'INSERT INTO "AuditLog" ' +
    '("user_id", "facility_id", "action", "target_table", "target_id", ' +
    '"old_value", "new_value", "created_at", "previous_hash", "current_hash") ' +
    'SELECT ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?, ? ' +
    'WHERE COALESCE(' +
    '(SELECT "current_hash" FROM "AuditLog" WHERE "facility_id" = ? ORDER BY "id" DESC LIMIT 1), ' +
    "'genesis') = ?";

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const lastLog = await env.DB.prepare(
      'SELECT "current_hash" AS current_hash ' +
        'FROM "AuditLog" WHERE "facility_id" = ? ORDER BY "id" DESC LIMIT 1'
    )
      .bind(params.facilityId)
      .first<{ current_hash: string | null }>();

    const previousHash = lastLog?.current_hash || 'genesis';
    const currentHash = await computeAuditLogCurrentHash({
      user_id: userId,
      facility_id: params.facilityId,
      action: params.action,
      target_table: params.targetTable,
      target_id: params.targetId,
      old_value: oldValStr,
      new_value: newValStr,
      previous_hash: previousHash,
    });

    const result = await env.DB.prepare(appendStatement)
      .bind(
        userId,
        params.facilityId,
        params.action,
        params.targetTable,
        params.targetId ?? null,
        oldValStr || null,
        newValStr || null,
        previousHash,
        currentHash,
        params.facilityId,
        previousHash
      )
      .run();

    if (result.meta.changes === 1) {
      const inserted = await env.DB.prepare(
        'SELECT "id" AS id, "created_at" AS created_at FROM "AuditLog" ' +
          'WHERE "facility_id" = ? AND "current_hash" = ? ORDER BY "id" DESC LIMIT 1'
      )
        .bind(params.facilityId, currentHash)
        .first<{ id: number; created_at: string }>();

      return {
        id: inserted?.id ?? result.meta.last_row_id,
        created_at: inserted?.created_at ?? new Date().toISOString(),
        current_hash: currentHash,
      };
    }
  }

  throw new Error('Could not append the audit chain for facility ' + params.facilityId + '.');
}

export function writeAuditLog(c: AuditExecutionContextLike, params: AuditLogWriteParams) {
  const user = c.get('user');
  if (!user || !user.id || !params.facilityId) return;

  try {
    const ctx = c.executionCtx;
    if (ctx && typeof ctx.waitUntil === 'function') {
      ctx.waitUntil(
        appendAuditLog(c.env, user.id, params).catch((error: unknown) => {
          console.error('[writeAuditLog] Failed to append audit log:', error);
        })
      );
      return;
    }
  } catch {
    // Falls back to direct execution if context has no ExecutionContext
  }

  appendAuditLog(c.env, user.id, params).catch((error: unknown) => {
    console.error('[writeAuditLog] Failed to append audit log in fallback:', error);
  });
}
