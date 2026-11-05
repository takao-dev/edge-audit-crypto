/**
 * Lightweight, zero-dependency CSV generator for Edge runtimes.
 * Supports RFC 4180 escaping and optional UTF-8 BOM for Microsoft Excel compatibility.
 */
export interface CsvOptions {
  includeBom?: boolean;
}

export function createCsv(
  rows: Array<Array<string | number | boolean | null | undefined>>,
  options: CsvOptions = {}
): Uint8Array {
  const escapeCell = (cell: unknown): string => {
    if (cell === null || cell === undefined) return '';
    const str = String(cell);
    if (str.includes('"') || str.includes(',') || str.includes('\n') || str.includes('\r')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const csvBody = rows.map((row) => row.map(escapeCell).join(',')).join('\r\n') + '\r\n';
  const encoder = new TextEncoder();
  const bodyBytes = encoder.encode(csvBody);

  if (options.includeBom) {
    const bom = new Uint8Array([0xef, 0xbb, 0xbf]);
    const withBom = new Uint8Array(bom.length + bodyBytes.length);
    withBom.set(bom, 0);
    withBom.set(bodyBytes, bom.length);
    return withBom;
  }

  return bodyBytes;
}
