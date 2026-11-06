/**
 * Lightweight, zero-dependency CSV generator for Edge runtimes.
 * Supports RFC 4180 escaping, Formula Injection (CSV DDE) defense, and optional UTF-8 BOM.
 */
export interface CsvOptions {
  includeBom?: boolean;
  /**
   * Neutralize spreadsheet formula injection (e.g. cells starting with =, +, -, @, \t, \r).
   * Enabled by default to prevent arbitrary command execution or data exfiltration in Microsoft Excel.
   */
  preventFormulaInjection?: boolean;
}

export function createCsv(
  rows: Array<Array<string | number | boolean | null | undefined>>,
  options: CsvOptions = {}
): Uint8Array {
  const sanitizeFormula = options.preventFormulaInjection !== false;

  const escapeCell = (cell: unknown): string => {
    if (cell === null || cell === undefined) return '';
    let str = String(cell);
    if (sanitizeFormula && str.length > 0 && /^[=+\-@\t\r]/.test(str)) {
      str = `'${str}`;
    }
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
