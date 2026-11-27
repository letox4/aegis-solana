/**
 * Client-side Zero-Knowledge / E2E Vulnerability PoC Encryption Engine.
 * Uses native browser WebCrypto API (AES-256-GCM + CSPRNG IV & Salt + SHA-256).
 * Plaintext PoCs never leave the researcher's device until cryptographic reveal.
 */

export interface AegisEncryptedEnvelope {
  protocol: "aegis-e2e-poc/1.0";
  algorithm: "AES-256-GCM";
  createdAt: string;
  targetBounty: string;
  researcherHandle: string;
  severity: number;
  ivB64: string;
  ciphertextB64: string;
  envelopeSha256: string;
  commitHashHex: string;
  aegisUri: string;
}

export interface AegisEncryptionBundle {
  envelope: AegisEncryptedEnvelope;
  decryptionKeyB64: string;
  generatedSalt: string;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64.trim());
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function generateSecureSalt(): string {
  const rand = new Uint8Array(12);
  crypto.getRandomValues(rand);
  return `aegis-${bytesToHex(rand)}`;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * Encrypts a confidential vulnerability PoC + technical report using a fresh 256-bit AES-GCM key.
 * Returns the encrypted envelope (safe to share / pin), the secret key (kept locally by researcher),
 * and a deterministic content-addressed `aegis-aes256://sha256/<digest>` URI for the on-chain PDA.
 */
export async function encryptPocEnvelope(params: {
  pocSummary: string;
  detailedReport: string;
  salt: string;
  targetBounty: string;
  researcherHandle: string;
  severity: number;
}): Promise<AegisEncryptionBundle> {
  const rawKey = new Uint8Array(32);
  const iv = new Uint8Array(12);
  crypto.getRandomValues(rawKey);
  crypto.getRandomValues(iv);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  const plaintextPayload = JSON.stringify({
    pocSummary: params.pocSummary,
    detailedReport: params.detailedReport,
    salt: params.salt,
    sealedAt: new Date().toISOString(),
  });

  const encryptedBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    new TextEncoder().encode(plaintextPayload)
  );

  const ivB64 = bytesToBase64(iv);
  const ciphertextB64 = bytesToBase64(new Uint8Array(encryptedBuf));
  const envelopeSha256 = await sha256Hex(`${ivB64}.${ciphertextB64}`);
  const commitHashHex = await sha256Hex(`${params.pocSummary.trim()}||${params.salt.trim()}`);
  const aegisUri = `aegis-aes256://sha256/${envelopeSha256.slice(0, 32)}`;

  const envelope: AegisEncryptedEnvelope = {
    protocol: "aegis-e2e-poc/1.0",
    algorithm: "AES-256-GCM",
    createdAt: new Date().toISOString(),
    targetBounty: params.targetBounty,
    researcherHandle: params.researcherHandle,
    severity: params.severity,
    ivB64,
    ciphertextB64,
    envelopeSha256,
    commitHashHex,
    aegisUri,
  };

  return {
    envelope,
    decryptionKeyB64: bytesToBase64(rawKey),
    generatedSalt: params.salt,
  };
}

/**
 * Decrypts and verifies an AEGIS AES-256-GCM envelope inside the browser.
 * Also re-verifies the SHA-256 commit digest against the decrypted preimage!
 */
export async function decryptPocEnvelope(
  envelope: AegisEncryptedEnvelope,
  decryptionKeyB64: string
): Promise<{
  pocSummary: string;
  detailedReport: string;
  salt: string;
  sealedAt: string;
  integrityVerified: boolean;
}> {
  const expectedEnvHash = await sha256Hex(`${envelope.ivB64}.${envelope.ciphertextB64}`);
  if (expectedEnvHash !== envelope.envelopeSha256) {
    throw new Error("Envelope SHA-256 integrity check failed — ciphertext has been tampered with.");
  }

  const rawKey = base64ToBytes(decryptionKeyB64);
  if (rawKey.length !== 32) {
    throw new Error("Invalid AES-256 key length (expected 32-byte Base64 key).");
  }
  const iv = base64ToBytes(envelope.ivB64);
  if (iv.length !== 12) {
    throw new Error("Invalid AES-GCM IV length (expected 12 bytes).");
  }
  const ciphertext = base64ToBytes(envelope.ciphertextB64);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    rawKey as BufferSource,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: iv as BufferSource },
    cryptoKey,
    ciphertext as BufferSource
  );

  const parsed = JSON.parse(new TextDecoder().decode(plainBuf));
  const recomputedCommit = await sha256Hex(`${String(parsed.pocSummary).trim()}||${String(parsed.salt).trim()}`);

  return {
    pocSummary: String(parsed.pocSummary || ""),
    detailedReport: String(parsed.detailedReport || ""),
    salt: String(parsed.salt || ""),
    sealedAt: String(parsed.sealedAt || ""),
    integrityVerified: recomputedCommit === envelope.commitHashHex,
  };
}
