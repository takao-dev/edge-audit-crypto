const escapePdfText = (value: string): string =>
  value.replace(/[\r\n\t]/g, ' ').replace(/[^\x20-\x7e]/g, () => {
    throw new Error('Text PDF currently supports printable ASCII only; use a Unicode-capable PDF renderer for other scripts');
  }).replace(/\\/g, '\\\\').replace(/\(/g, '\\(').replace(/\)/g, '\\)');

/** Creates a small, dependency-free text PDF for operational exports. */
export const createTextPdf = (title: string, lines: string[]): Uint8Array => {
  if (typeof title !== 'string' || !Array.isArray(lines) || lines.some((line) => typeof line !== 'string')) {
    throw new TypeError('PDF title and lines must be strings');
  }
  const contentLines = [title, '', ...lines].slice(0, 48);
  const commands = ['BT', '/F1 10 Tf', '50 780 Td'];
  contentLines.forEach((line, index) => {
    if (index > 0) commands.push('0 -15 Td');
    commands.push(`(${escapePdfText(line.slice(0, 150))}) Tj`);
  });
  commands.push('ET');
  const stream = commands.join('\n');
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
    `<< /Length ${new TextEncoder().encode(stream).byteLength} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];
  let pdf = '%PDF-1.4\n';
  const encoder = new TextEncoder();
  const offsets = [0];
  objects.forEach((object, index) => {
    offsets.push(encoder.encode(pdf).byteLength);
    pdf += `${index + 1} 0 obj\n${object}\nendobj\n`;
  });
  const xrefOffset = encoder.encode(pdf).byteLength;
  pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  offsets.slice(1).forEach((offset) => {
    pdf += `${String(offset).padStart(10, '0')} 00000 n \n`;
  });
  pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xrefOffset}\n%%EOF`;
  return encoder.encode(pdf);
};
