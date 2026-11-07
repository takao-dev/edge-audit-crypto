# edge-audit-crypto

[![CI](https://github.com/takao-dev/edge-audit-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/takao-dev/edge-audit-crypto/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/edge-audit-crypto.svg)](https://www.npmjs.com/package/edge-audit-crypto)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)

> **Cloudflare Workers、Cloudflare D1（SQLite）、および各種エッジ環境に特化した、ゼロ依存・本番水準のセキュリティ ＆ 運用ツールキット。**

サーバーレス並行リクエスト下でのハッシュチェーン分岐を防ぐ **楽観的 CAS（Compare-And-Set）改ざん検知監査ログ**、本番無停止で平文カラムを暗号化移行できる **AES-256-GCM フィールド暗号化（FLE）**、平文を一切保存しない **検索可能暗号化（Blind Indexing）**、そしてワーカーの容量制限（1MB）に抵触しない **ゼロ依存 PDF / ZIP / Excel対応CSV 生成器** を提供します。

[English README is available here](./README.md)

---

## 🚀 主な機能

1. **楽観的 CAS 監査ログハッシュチェーン (`appendAuditLog`, `verifyAuditLogChain`)**
   - 分散サーバーレス環境で各ログレコードを SHA-256 で暗号学的に連鎖。
   - 複数インスタンスからの同時並行書き込み時にも、SQLite/D1 の単一クエリ CAS パターンによりチェーンの分岐（フォーク）を物理的に防止。
   - 個人情報（PII）にアクセスすることなく、ハッシュの整合性のみを外部から検証可能。
2. **無停止 AES-256-GCM フィールド暗号化 (`encryptField`, `decryptField`)**
   - Web Crypto API による認証付き暗号化（AEAD）。
   - 28バイトのエンベロープ形式（`12バイトIV + 暗号文 + 16バイト認証タグ`）。
   - `allowLegacyPlaintext` オプションにより、本番サービスを停止することなく、既存の平文レコードを稼働中に順次暗号化へ移行可能。
3. **検索可能暗号化 Blind Indexing (`computeBlindIndex`)**
   - ソルト付き HMAC-SHA256 により、平文を復号することなく `WHERE email_bindex = ?` などの高速な完全一致インデックス検索を実現。
4. **ゼロダウンタイム鍵ローテーション (`rotateEncryptedField`)**
   - 旧マスターキーで復号し、新しいランダム IV で新マスターキー暗号化を実行する無損失ローテーション。
5. **超軽量エッジ向けファイルジェネレータ (`createTextPdf`, `createStoredMultiZip`, `createCsv`)**
   - WASM や巨大な canvas 依存なしに数キロバイトで PDF 1.4 を動的生成。
   - CRC-32 および UTF-8 日本語ファイル名に完全対応した ZIP アーカイブ生成。
   - スプレッドシート数式インジェクション（CSV DDE）対策および Microsoft Excel の文字化けを防ぐ UTF-8 BOM に対応した RFC 4180 CSV 生成。

---

## 📦 インストール

```bash
npm install edge-audit-crypto
```

要件:
- Node.js `>= 18.0.0` または Cloudflare Workers / Fastly Compute / Deno / Bun

---

## 💡 使用方法

### 1. 楽観的 CAS 改ざん検知監査ログ

Cloudflare D1（SQLite）テーブル定義例：

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

#### ログの追加（Cloudflare Worker）

```typescript
import { appendAuditLog } from 'edge-audit-crypto';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const success = await appendAuditLog(
      env,
      userId,
      {
        facilityId: 101,
        action: 'user.update',
        targetTable: 'patients',
        targetId: 402,
        oldValue: { status: 'pending' },
        newValue: { status: 'approved' },
      },
      { maxRetries: 5, baseRetryDelayMs: 30 }
    );

    return new Response(success ? 'OK' : 'Conflict', { status: success ? 200 : 409 });
  }
};
```

#### ハッシュチェーンの改ざん検証

```typescript
import { verifyAuditLogChain } from 'edge-audit-crypto';

const rows = await env.DB.prepare('SELECT * FROM audit_logs ORDER BY created_at ASC, id ASC').all();
const result = await verifyAuditLogChain(rows.results);

if (result.ok) {
  console.log(`監査チェーン正常: 全 ${result.total} 件の整合性を確認しました。`);
} else {
  console.error('改ざんを検知しました！', result.issues);
}
```

---

### 2. フィールド暗号化 ＆ 検索可能暗号化 (FLE)

```typescript
import { encryptField, decryptField, computeBlindIndex, rotateEncryptedField } from 'edge-audit-crypto';

const masterKey = env.FLE_MASTER_KEY; // 32バイトの Base64 文字列

// 1. 暗号化して保存
const ciphertext = await encryptField('user@example.com', masterKey);

// 2. 移行モードでの復号（既存の平文レコードは平文のまま透過的に読み出し可能）
const email = await decryptField(dbRow.email, masterKey, { allowLegacyPlaintext: true });

// 3. 検索可能暗号化（平文を保存せずに完全一致検索用インデックスを生成）
const emailIndex = await computeBlindIndex('user@example.com', env.BLIND_INDEX_KEY);
// -> SELECT * FROM users WHERE email_bindex = ?

// 4. 暗号鍵のローテーション
const newCiphertext = await rotateEncryptedField(ciphertext, oldKey, newKey);
```

---

### 3. エッジ PDF / ZIP / CSV 生成

```typescript
import { createTextPdf, createStoredMultiZip, createCsv } from 'edge-audit-crypto';

// 1. PDF 生成
const pdfBytes = createTextPdf('監査報告書', ['対象ID: #1042', 'ステータス: 適合']);

// 2. CSV 生成（Excel文字化け防止BOM ＆ 数式インジェクション対策済み）
const csvBytes = createCsv([
  ['ID', '名前', '役職'],
  [1, '山田 太郎', '管理者'],
], { includeBom: true });

// 3. ZIP アーカイブにひとまとめにしてレスポンス
const zipBytes = createStoredMultiZip([
  { filename: 'report.pdf', content: pdfBytes },
  { filename: 'export.csv', content: csvBytes },
]);

return new Response(zipBytes, {
  headers: {
    'Content-Type': 'application/zip',
    'Content-Disposition': 'attachment; filename="export.zip"',
  },
});
```

---

## 📄 ライセンス

MIT License © 2026 takao-dev
