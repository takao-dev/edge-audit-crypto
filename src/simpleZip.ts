const crcTable = Array.from({ length: 256 }, (_, index) => {
  let value = index;
  for (let bit = 0; bit < 8; bit++) value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
  return value >>> 0;
});

const crc32 = (data: Uint8Array): number => {
  let value = 0xffffffff;
  for (const byte of data) value = crcTable[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
};

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
};

const header = (size: number): DataView => new DataView(new ArrayBuffer(size));

export interface StoredZipFileEntry {
  filename: string;
  content: string | Uint8Array;
}

/** Creates a standards-compliant ZIP containing one or more uncompressed UTF-8 files. */
export const createStoredMultiZip = (entries: ReadonlyArray<StoredZipFileEntry>): Uint8Array => {
  if (!Array.isArray(entries) || entries.length > 65_535) throw new RangeError('ZIP requires at most 65535 entries');
  const encoder = new TextEncoder();
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let localOffset = 0;
  const seenNames = new Set<string>();
  let totalDataBytes = 0;

  for (const entry of entries) {
    if (!entry || typeof entry.filename !== 'string' || (!((typeof entry.content === 'string') || entry.content instanceof Uint8Array))) {
      throw new TypeError('ZIP entries require a string filename and string or Uint8Array content');
    }
    const namePath = entry.filename.replace(/\\/g, '/');
    if (!namePath || namePath.startsWith('/') || /^[A-Za-z]:/.test(namePath) || /[\u0000-\u001f\u007f]/.test(namePath) || namePath.split('/').some((part: string) => part === '' || part === '.' || part === '..')) {
      throw new Error('ZIP entry filenames must be safe relative paths');
    }
    if (seenNames.has(namePath)) throw new Error('ZIP entry filenames must be unique');
    seenNames.add(namePath);
    const name = encoder.encode(entry.filename);
    const data = typeof entry.content === 'string' ? encoder.encode(entry.content) : entry.content;
    totalDataBytes += data.byteLength;
    if (name.byteLength > 65_535 || data.byteLength > 0xffff_ffff || localOffset > 0xffff_ffff || totalDataBytes > 100 * 1024 * 1024) {
      throw new RangeError('ZIP entry or archive exceeds supported size limits');
    }
    const checksum = crc32(data);

    const local = header(30 + name.length);
    local.setUint32(0, 0x04034b50, true);
    local.setUint16(4, 20, true);
    local.setUint16(6, 0x800, true);
    local.setUint16(8, 0, true);
    local.setUint32(14, checksum, true);
    local.setUint32(18, data.length, true);
    local.setUint32(22, data.length, true);
    local.setUint16(26, name.length, true);
    new Uint8Array(local.buffer).set(name, 30);
    const localBytes = new Uint8Array(local.buffer);

    const central = header(46 + name.length);
    central.setUint32(0, 0x02014b50, true);
    central.setUint16(4, 20, true);
    central.setUint16(6, 20, true);
    central.setUint16(8, 0x800, true);
    central.setUint16(10, 0, true);
    central.setUint32(16, checksum, true);
    central.setUint32(20, data.length, true);
    central.setUint32(24, data.length, true);
    central.setUint16(28, name.length, true);
    central.setUint32(42, localOffset, true);
    new Uint8Array(central.buffer).set(name, 46);
    const centralBytes = new Uint8Array(central.buffer);

    localParts.push(localBytes, data);
    centralParts.push(centralBytes);
    localOffset += localBytes.length + data.length;
  }

  const centralDirectory = concat(...centralParts);
  if (centralDirectory.byteLength > 0xffff_ffff || localOffset + centralDirectory.byteLength > 0xffff_ffff) {
    throw new RangeError('ZIP archive exceeds the classic ZIP format size limit');
  }
  const end = header(22);
  end.setUint32(0, 0x06054b50, true);
  end.setUint16(8, entries.length, true);
  end.setUint16(10, entries.length, true);
  end.setUint32(12, centralDirectory.length, true);
  end.setUint32(16, localOffset, true);

  return concat(...localParts, centralDirectory, new Uint8Array(end.buffer));
};

/** Creates a standards-compliant ZIP containing one uncompressed UTF-8 file. */
export const createStoredZip = (filename: string, text: string): Uint8Array =>
  createStoredMultiZip([{ filename, content: text }]);
