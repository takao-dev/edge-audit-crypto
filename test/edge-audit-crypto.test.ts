import assert from 'node:assert/strict';
import test from 'node:test';
import {
  appendAuditLog,
  buildAuditLogHashInput,
  computeAuditLogCurrentHash,
  createStoredMultiZip,
  createStoredZip,
  createTextPdf,
  decryptField,
  encryptField,
  isLikelyEncryptedField,
  normalizePublicIdentifier,
  verifyAuditLogChain,
  computeBlindIndex,
  rotateEncryptedField,
  createCsv,
  type AuditLogVerificationRecord,
  type D1DatabaseLike,
} from '../dist/index.js';

const masterKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(7)));

test('field-level encryption round-trips, detects ciphertext shape, and supports migration flag', async () => {
  // Plaintext without migration flag should return null
  assert.equal(await decryptField('管理者', masterKey), null);
  // Plaintext with migration flag should return plaintext as fallback
  assert.equal(await decryptField('管理者', masterKey, { allowLegacyPlaintext: true }), '管理者');

  const encrypted = await encryptField('管理者', masterKey);
  assert.ok(encrypted);
  assert.equal(isLikelyEncryptedField(encrypted), true);
  assert.equal(await decryptField(encrypted, masterKey), '管理者');

  // Empty string encryption
  const encryptedEmpty = await encryptField('', masterKey);
  assert.equal(await decryptField(encryptedEmpty, masterKey), '');

  // Tampered ciphertext fails authentication check
  const tampered = `${encrypted.slice(0, -2)}AA`;
  assert.equal(await decryptField(tampered, masterKey), null);

  // Identifier normalization
  assert.equal(await normalizePublicIdentifier('CD3MA2AAAB', masterKey), 'CD3MA2AAAB');
  assert.equal(await normalizePublicIdentifier(encrypted, masterKey), '管理者');
  assert.equal(await normalizePublicIdentifier(null, masterKey), null);
  assert.equal(await normalizePublicIdentifier(undefined, masterKey), undefined);
});

test('optimistic CAS audit log append and PII-free chain verifier detect tampering', async () => {
  assert.equal(
    buildAuditLogHashInput({
      user_id: 10,
      facility_id: 1,
      action: 'update',
      target_table: null,
      target_id: null,
      old_value: null,
      new_value: null,
      previous_hash: null,
    }),
    'genesis|10|update|undefined|undefined||'
  );

  const rows: AuditLogVerificationRecord[] = [];
  let nextId = 1;
  const db: D1DatabaseLike = {
    prepare(sql: string) {
      let values: unknown[] = [];
      const statement = {
        bind(...args: unknown[]) {
          values = args;
          return statement;
        },
        async first<T>() {
          if (sql.includes('SELECT "current_hash" AS current_hash')) {
            const facilityId = Number(values[0]);
            const row = [...rows].reverse().find((r) => r.facility_id === facilityId);
            return (row ? { current_hash: row.current_hash } : null) as T | null;
          }
          const currentHash = String(values[1]);
          const row = rows.find((r) => r.current_hash === currentHash);
          return (row ? { id: row.id, created_at: row.created_at } : null) as T | null;
        },
        async run() {
          const userId = Number(values[0]);
          const facilityId = Number(values[1]);
          const action = String(values[2]);
          const targetTable = values[3] as string | null;
          const targetId = values[4] as number | null;
          const oldValue = values[5] as string | null;
          const newValue = values[6] as string | null;
          const previousHash = String(values[7]);
          const currentHash = String(values[8]);
          const expectedPrevious =
            rows.filter((r) => r.facility_id === facilityId).at(-1)?.current_hash ?? 'genesis';
          if (previousHash !== expectedPrevious) {
            return { meta: { changes: 0, last_row_id: 0 } };
          }
          const row: AuditLogVerificationRecord = {
            id: nextId++,
            user_id: userId,
            facility_id: facilityId,
            action,
            target_table: targetTable,
            target_id: targetId,
            old_value: oldValue,
            new_value: newValue,
            previous_hash: previousHash,
            current_hash: currentHash,
            created_at: new Date().toISOString(),
          };
          rows.push(row);
          return { meta: { changes: 1, last_row_id: row.id } };
        },
      };
      return statement;
    },
  };

  await appendAuditLog({ DB: db }, 10, {
    facilityId: 1,
    action: 'create',
    targetTable: 'children',
    targetId: 7,
    newValue: { name: 'A' },
  });
  await appendAuditLog({ DB: db }, 11, {
    facilityId: 1,
    action: 'update',
    targetTable: 'children',
    targetId: 7,
    newValue: { name: 'B' },
  });

  const valid = await verifyAuditLogChain(rows);
  assert.equal(valid.ok, true);
  assert.equal(valid.total, 2);
  assert.equal(valid.facilities, 1);
  assert.equal(valid.issues.length, 0);

  // Tamper middle log
  const tampered = rows.map((r, i) => (i === 0 ? { ...r, current_hash: 'tampered' } : r));
  const invalid = await verifyAuditLogChain(tampered);
  assert.equal(invalid.ok, false);
  assert.deepEqual(
    invalid.issues.map((i) => i.kind),
    ['current-hash-mismatch', 'previous-hash-mismatch']
  );
  assert.ok(await computeAuditLogCurrentHash(rows[0]));
});

test('createTextPdf and createStoredMultiZip produce valid binary outputs', () => {
  const pdf = new TextDecoder().decode(createTextPdf('Report (June)', ['line 1', 'line 2']));
  assert.ok(pdf.startsWith('%PDF-1.4\n'));
  assert.ok(pdf.includes('(Report \\(June\\)) Tj'));
  assert.ok(pdf.includes('(line 1) Tj'));
  assert.ok(pdf.includes('%%EOF'));

  const zip = createStoredZip('報告.txt', '123456789');
  const view = new DataView(zip.buffer, zip.byteOffset, zip.byteLength);
  assert.equal(view.getUint32(0, true), 0x04034b50); // Local file header signature
  assert.equal(view.getUint32(14, true), 0xcbf43926); // CRC-32 of '123456789'

  const multiZip = createStoredMultiZip([
    { filename: 'a.txt', content: 'A' },
    { filename: 'b.bin', content: new Uint8Array([0x01, 0x02, 0x03]) },
  ]);
  const multiView = new DataView(multiZip.buffer, multiZip.byteOffset, multiZip.byteLength);
  // Total entries in central directory (offset -22 + 8)
  assert.equal(multiView.getUint16(multiZip.byteLength - 22 + 8, true), 2);
});

test('computeBlindIndex and rotateEncryptedField support searchable FLE and key rotation', async () => {
  const blindKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(9)));
  const newMasterKey = btoa(String.fromCharCode(...new Uint8Array(32).fill(8)));

  // Blind index deterministic hashing
  const idx1 = await computeBlindIndex('user@example.com', blindKey);
  const idx2 = await computeBlindIndex(' USER@EXAMPLE.COM ', blindKey);
  assert.equal(idx1, idx2);
  assert.match(idx1!, /^[a-f0-9]{64}$/);

  const idxDiff = await computeBlindIndex('other@example.com', blindKey);
  assert.notEqual(idx1, idxDiff);

  // Key rotation
  const original = 'Confidential Patient Record';
  const oldCipher = await encryptField(original, masterKey);
  assert.ok(oldCipher);

  const rotated = await rotateEncryptedField(oldCipher, masterKey, newMasterKey);
  assert.ok(rotated);
  assert.notEqual(rotated, oldCipher);

  // Decrypt with new master key
  assert.equal(await decryptField(rotated, newMasterKey), original);
  // Old key can no longer decrypt rotated ciphertext
  assert.equal(await decryptField(rotated, masterKey), null);
});

test('createCsv generates valid RFC 4180 CSV with optional BOM and formula injection defense', () => {
  const rows = [
    ['Name', 'Age', 'Bio', 'FormulaInjection'],
    ['Alice', 30, 'Hello, World!', '=1+1'],
    ['Bob', 25, 'Line 1\nLine "2"', '@SUM(A1:A10)'],
  ];

  const csv = createCsv(rows);
  const text = new TextDecoder().decode(csv);
  assert.ok(text.includes('"Hello, World!"'));
  assert.ok(text.includes('"Line 1\nLine ""2"""'));
  // Formula injection should be neutralized with prepended quote
  assert.ok(text.includes("'=1+1"));
  assert.ok(text.includes("'@SUM(A1:A10)"));
  assert.equal(csv[0], 0x4e); // 'N'

  // When disabled
  const rawCsv = createCsv([['=RAW']], { preventFormulaInjection: false });
  assert.ok(new TextDecoder().decode(rawCsv).startsWith('=RAW'));

  const csvBom = createCsv(rows, { includeBom: true });
  assert.equal(csvBom[0], 0xef);
  assert.equal(csvBom[1], 0xbb);
  assert.equal(csvBom[2], 0xbf);
});
