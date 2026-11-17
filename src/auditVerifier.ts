import { computeAuditLogCurrentHash, type AuditLogHashRecord } from './audit.js';

export type AuditLogVerificationIssue = {
  facilityId: number;
  auditLogId: number;
  kind: 'missing-current-hash' | 'previous-hash-mismatch' | 'current-hash-mismatch' | 'legacy-hash-version';
  message: string;
};

export type AuditLogVerificationResult = {
  ok: boolean;
  total: number;
  facilities: number;
  issues: AuditLogVerificationIssue[];
};

export type AuditLogVerificationRecord = AuditLogHashRecord & {
  id: number;
  created_at: Date | string;
};

const compareRecords = (left: AuditLogVerificationRecord, right: AuditLogVerificationRecord) => left.id - right.id;

/**
 * Verifies facility-scoped audit chains without exposing PII in the result.
 * Records follow their database insertion IDs, matching append order.
 */
export const verifyAuditLogChain = async (
  records: readonly AuditLogVerificationRecord[]
): Promise<AuditLogVerificationResult> => {
  const grouped = new Map<number, AuditLogVerificationRecord[]>();
  for (const record of records) {
    const facilityRecords = grouped.get(record.facility_id) || [];
    facilityRecords.push(record);
    grouped.set(record.facility_id, facilityRecords);
  }

  const issues: AuditLogVerificationIssue[] = [];

  for (const [facilityId, facilityRecords] of grouped) {
    facilityRecords.sort(compareRecords);
    let expectedPreviousHash = 'genesis';

    for (const record of facilityRecords) {
      if (!record.current_hash) {
        issues.push({
          facilityId,
          auditLogId: record.id,
          kind: 'missing-current-hash',
          message: 'current_hash is missing',
        });
        expectedPreviousHash = '';
        continue;
      }

      if ((record.previous_hash ?? 'genesis') !== expectedPreviousHash) {
        issues.push({
          facilityId,
          auditLogId: record.id,
          kind: 'previous-hash-mismatch',
          message: 'previous_hash does not match the preceding audit log',
        });
      }

      if (!/^v2_[0-9a-f]{64}$/.test(record.current_hash)) {
        issues.push({ facilityId, auditLogId: record.id, kind: 'legacy-hash-version', message: 'record uses the pre-v2 ambiguous hash format and cannot be independently verified' });
        expectedPreviousHash = record.current_hash;
        continue;
      }

      const expectedCurrentHash = await computeAuditLogCurrentHash(record);
      if (record.current_hash !== expectedCurrentHash) {
        issues.push({
          facilityId,
          auditLogId: record.id,
          kind: 'current-hash-mismatch',
          message: 'current_hash does not match the serialized audit log values',
        });
      }

      expectedPreviousHash = record.current_hash;
    }
  }

  return {
    ok: issues.length === 0,
    total: records.length,
    facilities: grouped.size,
    issues,
  };
};
