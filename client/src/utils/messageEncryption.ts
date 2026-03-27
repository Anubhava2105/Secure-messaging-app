/**
 * Message encryption and decryption utilities.
 * Uses AES-GCM-256 for symmetric encryption.
 */

import { aesGcmEncrypt, aesGcmDecrypt } from "../crypto/symmetric/aesgcm";
import {
  bytesToBase64,
  base64ToBytes,
  stringToBytes,
  bytesToString,
  concatBytes,
} from "../crypto/utils/encoding";
import { getRandomBytes } from "../crypto/utils/random";
import { NONCE_SIZE } from "../constants";
import type { Session } from "../crypto/hybrid/handshake";

/**
 * Encrypt a message using the session key.
 * Format: [nonce (12 bytes)][ciphertext]
 *
 * @param content - Plaintext message content
 * @param session - Session containing encryption keys
 * @returns Base64-encoded encrypted blob
 */
export async function encryptMessage(
  content: string,
  session: Session,
): Promise<string> {
  const nonce = getRandomBytes(NONCE_SIZE);
  const plaintext = stringToBytes(content);
  const ciphertext = await aesGcmEncrypt(
    session.keys.encryptionKey,
    nonce,
    plaintext,
  );
  const combined = concatBytes(nonce, ciphertext);
  return bytesToBase64(combined);
}

/**
 * Decrypt a message using the session key.
 *
 * @param encryptedBlob - Base64-encoded encrypted blob
 * @param session - Session containing encryption keys
 * @returns Decrypted plaintext message
 */
export async function decryptMessage(
  encryptedBlob: string,
  session: Session,
): Promise<string> {
  const combined = base64ToBytes(encryptedBlob);
  const nonce = combined.slice(0, NONCE_SIZE);
  const ciphertext = combined.slice(NONCE_SIZE);
  const plaintext = await aesGcmDecrypt(
    session.keys.encryptionKey,
    nonce,
    ciphertext,
  );
  return bytesToString(plaintext);
}
