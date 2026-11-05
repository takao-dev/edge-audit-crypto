# edge-audit-crypto

[![CI](https://github.com/takaodev/edge-audit-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/takaodev/edge-audit-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/edge-audit-crypto.svg)](https://www.npmjs.com/package/edge-audit-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> **Zero-dependency, production-grade security and operational toolkit for Cloudflare Workers, Cloudflare D1 (SQLite), and Edge runtimes.**

Modern edge runtimes like Cloudflare Workers and D1 have strict constraints: bundle size limits, lack of native Node.js binaries, and high concurrency without traditional database table locks. `edge-audit-crypto` solves these edge architectures cleanly with zero runtime dependencies.

---

## Features

1. **Optimistic CAS Audit Hash Chains (`appendAuditLog`, `verifyAuditLogChain`)**
   - Cryptographic tamper-evident hash chaining (SHA-256) across distributed serverless executions.
   - Prevents hash chain forks under concurrent writes using an atomic single-query Compare-And-Set (CAS) pattern in SQLite/D1.
   - PII-free external audit verification: checks hash integrity without requiring access to sensitive payload data.
2. **Zero-Downtime AES-256-GCM Field-Level Encryption (`encryptField`, `decryptField`)**
   - Authenticated encryption (AEAD) using the standard Web Crypto API.
   - 28-byte envelope format (`12-byte IV + ciphertext + 16-byte Auth Tag`) serialized as URL-safe Base64.
   - Dual-mode decryption with `allowLegacyPlaintext`: enables live, zero-downtime database field encryption migrations without batch offline downtime.
3. **Ultra-Lightweight Edge PDF & ZIP Generators (`createTextPdf`, `createStoredMultiZip`)**
   - Zero-dependency PDF 1.4 generation in standard edge JavaScript without heavy canvas/WASM dependencies.
   - Zero-compression ZIP archive builder with proper UTF-8 filenames and CRC-32 checksum calculation.

---

## Installation

```bash
npm install edge-audit-crypto
```

Requirements:
- Node.js `>= 18.0.0` or Cloudflare Workers / Fastly Compute / Deno / Bun.

---

## Quick Start & Usage

### 1. Tamper-Evident Audit Log with Optimistic CAS

Cloudflare D1 is SQLite at the edge. Because multiple worker instances handle concurrent writes, naive `SELECT current_hash` followed by `INSERT` causes chain forking. `edge-audit-crypto` uses an atomic CAS query with jittered backoff retry:

#### Database Schema (D1 Migration SQL)

```sql
CREATE TABLE audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  facility_id INTEGER NOT NULL,
  user_id INTEGER NOT NULL,
  action TEXT NOT NULL,
  target_table TEXT,
  target_id INTEGER,
  old_value TEXT,
  new_value TEXT,
  previous_hash TEXT NOT NULL,
  current_hash TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_facility_id ON audit_logs(facility_id, id DESC);
CREATE UNIQUE INDEX idx_audit_logs_current_hash ON audit_logs(current_hash);
```

#### In Cloudflare Worker Handler

```typescript
import { appendAuditLog } from 'edge-audit-crypto';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Automatically reads the latest chain head and performs atomic CAS insert with retries
    const success = await appendAuditLog(
      env,
      userId,
      {
        facilityId: 101,
        action: 'patient.discharge',
        targetTable: 'patients',
        targetId: 402,
        oldValue: { status: 'admitted' },
        newValue: { status: 'discharged' },
      },
      {
        maxRetries: 5,
        baseRetryDelayMs: 30,
      }
    );

    return new Response(success ? 'Logged' : 'Conflict', { status: success ? 200 : 409 });
  }
};
```

#### Verifying Audit Log Chain Integrity

```typescript
import { verifyAuditLogChain } from 'edge-audit-crypto';

// Fetch rows for an organization or facility
const rows = await env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at ASC, id ASC').all();

const result = await verifyAuditLogChain(rows.results);
if (result.ok) {
  console.log(`Audit chain intact! Verified ${result.total} records across ${result.facilities} facilities.`);
} else {
  console.error('Tampering detected!', result.issues);
  // Example issue: { kind: 'previous-hash-mismatch', auditLogId: 42, facilityId: 101 }
}
```

---

### 2. Zero-Downtime Field-Level Encryption (FLE)

Store sensitive columns (e.g. medical IDs, personal identification numbers, access tokens) encrypted at rest in D1/Postgres with smooth migration.

```typescript
import { encryptField, decryptField, normalizePublicIdentifier } from 'edge-audit-crypto';

// Master key must be 32 bytes (256-bit), provided as Base64 string
const masterKey = env.FLE_MASTER_KEY; // e.g. btoa(32 random bytes)

// 1. Encrypt field before saving
const ciphertext = await encryptField('MY-SECRET-SSN-123', masterKey);

// 2. Decrypt in zero-downtime migration mode:
// If the DB field still contains legacy plaintext, it safely falls back to plaintext.
const value = await decryptField(dbValue, masterKey, { allowLegacyPlaintext: true });

// 3. Normalize identifiers (handles encrypted tokens or legacy alphanumeric keys interchangeably)
const cleanId = await normalizePublicIdentifier(incomingParam, masterKey);
```

---

### 3. Edge PDF & ZIP Generators

Generate export files on-the-fly without heavy external dependencies.

#### Generating PDF Documents

```typescript
import { createTextPdf } from 'edge-audit-crypto';

const pdfBytes = createTextPdf('Monthly Activity Report', [
  'Account ID: ACC-98213',
  'Export Date: 2026-11-05',
  'Total Actions: 1,420',
  'Status: Verified Compliant'
]);

return new Response(pdfBytes, {
  headers: {
    'Content-Type': 'application/pdf',
    'Content-Disposition': 'attachment; filename="report.pdf"',
  },
});
```

#### Generating Multi-File ZIP Archives

```typescript
import { createStoredMultiZip } from 'edge-audit-crypto';

const zipBytes = createStoredMultiZip([
  {
    filename: 'export/summary.txt',
    content: 'Export summary info...',
  },
  {
    filename: 'export/data.csv',
    content: 'id,name,value\n1,Alice,100\n2,Bob,200\n',
  },
  {
    filename: 'export/report.pdf',
    content: pdfBytes, // Uint8Array supported
  },
]);

return new Response(zipBytes, {
  headers: {
    'Content-Type': 'application/zip',
    'Content-Disposition': 'attachment; filename="bundle.zip"',
  },
});
```

---

## Subpath Imports

For optimal bundle tree-shaking in modern bundlers:

```typescript
import { appendAuditLog } from 'edge-audit-crypto/audit';
import { verifyAuditLogChain } from 'edge-audit-crypto/auditVerifier';
import { encryptField, decryptField } from 'edge-audit-crypto/crypto';
import { createTextPdf } from 'edge-audit-crypto/pdf';
import { createStoredZip, createStoredMultiZip } from 'edge-audit-crypto/zip';
```

---

## Security Model

- **Authentication**: AES-256-GCM uses a 128-bit authentication tag, making bit-flipping attacks detectable.
- **IV Generation**: Uses `crypto.getRandomValues(new Uint8Array(12))` for each encryption operation. Never reuses IVs.
- **Hash Algorithm**: SHA-256 via Web Crypto API (`crypto.subtle.digest`).
- **Zero-Dependency**: No external npm packages at runtime. Immune to supply chain dependency attacks.

---

## License

MIT © [takaodev](https://github.com/takaodev)
