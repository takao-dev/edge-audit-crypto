/**
 * Utility for Field-Level Encryption (FLE) using Web Crypto API.
 * Uses AES-256-GCM for authenticated encryption with zero-downtime plaintext migration support.
 */

const cryptoKeyCache = new Map<string, CryptoKey>();

function base64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  const binary = atob(base64);
  const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(new ArrayBuffer(binary.length));
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function getCryptoKey(
  masterKeyBase64: string,
  usage: 'encrypt' | 'decrypt'
): Promise<CryptoKey> {
  const cacheKey = `${masterKeyBase64}:${usage}`;
  let key = cryptoKeyCache.get(cacheKey);
  if (!key) {
    const keyBuffer = base64ToUint8Array(masterKeyBase64);
    key = await crypto.subtle.importKey('raw', keyBuffer, { name: 'AES-GCM' }, false, [usage]);
    cryptoKeyCache.set(cacheKey, key);
  }
  return key;
}

/**
 * Encrypt a string using the master key.
 * Returns a base64 string containing: IV (12 bytes) + Ciphertext + Tag (16 bytes)
 */
export async function encryptField(
  plainText: string | null | undefined,
  masterKeyBase64: string
): Promise<string | null | undefined> {
  if (!plainText) return plainText;

  const encoder = new TextEncoder();
  const data = encoder.encode(plainText);

  const key = await getCryptoKey(masterKeyBase64, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);

  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(encrypted), iv.length);

  return btoa(String.fromCharCode(...combined));
}

export type DecryptFieldOptions = {
  /**
   * Allow an existing plaintext value to pass through during a controlled
   * migration. This must be explicitly enabled by the deployment binding.
   */
  allowLegacyPlaintext?: boolean;
};

export const allowsLegacyPlaintextFields = (env: {
  ALLOW_LEGACY_PLAINTEXT_FIELDS?: string;
}): boolean => env.ALLOW_LEGACY_PLAINTEXT_FIELDS === 'true';

export function isLikelyEncryptedField(value: string): boolean {
  try {
    const decoded = base64ToUint8Array(value);
    return decoded.length >= 28;
  } catch {
    return false;
  }
}

export async function normalizePublicIdentifier(
  value: string | null | undefined,
  masterKeyBase64?: string
): Promise<string | null | undefined> {
  if (!value || !masterKeyBase64 || !isLikelyEncryptedField(value)) return value;
  return (await decryptField(value, masterKeyBase64)) ?? null;
}

export async function decryptField(
  encryptedBase64: string | null | undefined,
  masterKeyBase64: string,
  options: DecryptFieldOptions = {}
): Promise<string | null | undefined> {
  if (!encryptedBase64) return encryptedBase64;

  const legacyValue = () => (options.allowLegacyPlaintext ? encryptedBase64 : null);

  let combined: Uint8Array<ArrayBuffer>;
  try {
    combined = base64ToUint8Array(encryptedBase64);
  } catch {
    return legacyValue();
  }

  // AES-GCM data must include a 12-byte IV and a 16-byte authentication tag (28 bytes min).
  if (combined.length < 28) return legacyValue();

  try {
    const iv = combined.slice(0, 12);
    const data = combined.slice(12);
    const key = await getCryptoKey(masterKeyBase64, 'decrypt');
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return new TextDecoder().decode(decrypted);
  } catch {
    if (options.allowLegacyPlaintext) {
      return encryptedBase64;
    }
    return null;
  }
}

export async function computeHash(data: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export function timingSafeEqual(a: string, b: string): boolean {
  let result = 0;
  if (a.length !== b.length) {
    b = a;
    result = 1;
  }
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

export function generateRandomToken(bytes = 32): string {
  const array = new Uint8Array(bytes);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Computes a deterministic, salted HMAC-SHA256 blind index for searchable field-level encryption.
 * Allows exact-match database queries (e.g., WHERE email_bindex = ?) without exposing plaintext.
 */
export async function computeBlindIndex(
  plainText: string | null | undefined,
  secretKeyBase64: string
): Promise<string | null | undefined> {
  if (!plainText) return plainText;
  const normalized = plainText.trim().toLowerCase();
  const keyBuffer = base64ToUint8Array(secretKeyBase64);
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    keyBuffer,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const signature = await crypto.subtle.sign(
    'HMAC',
    cryptoKey,
    new TextEncoder().encode(normalized)
  );
  const hashArray = Array.from(new Uint8Array(signature));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Seamlessly rotates the encryption key for a field.
 * Decrypts with old master key and re-encrypts with new master key using a fresh random IV.
 */
export async function rotateEncryptedField(
  ciphertext: string,
  oldMasterKeyBase64: string,
  newMasterKeyBase64: string,
  options?: DecryptFieldOptions
): Promise<string | null> {
  const decrypted = await decryptField(ciphertext, oldMasterKeyBase64, options);
  if (decrypted === null || decrypted === undefined) return null;
  const reEncrypted = await encryptField(decrypted, newMasterKeyBase64);
  return reEncrypted ?? null;
}
