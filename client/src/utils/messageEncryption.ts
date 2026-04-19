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

export interface MessageAuthContext {
  messageId: string;
  senderId: string;
  recipientId: string;
  groupId?: string;
  groupEventType?: "group_message" | "group_membership";
  groupMembershipCommitment?: string;
}

function buildMessageAad(context: MessageAuthContext): Uint8Array {
  const canonical = [
    "v1",
    context.messageId,
    context.senderId,
    context.recipientId,
    context.groupId ?? "",
    context.groupEventType ?? "",
    context.groupMembershipCommitment ?? "",
  ].join("|");

  return stringToBytes(canonical);
}

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
  messageKey: Uint8Array,
  authContext?: MessageAuthContext,
): Promise<string> {
  const nonce = getRandomBytes(NONCE_SIZE);
  const plaintext = stringToBytes(content);
  const aad = authContext ? buildMessageAad(authContext) : undefined;
  const ciphertext = await aesGcmEncrypt(messageKey, nonce, plaintext, aad);
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
  messageKey: Uint8Array,
  authContext?: MessageAuthContext,
): Promise<string> {
  const combined = base64ToBytes(encryptedBlob);
  const nonce = combined.slice(0, NONCE_SIZE);
  const ciphertext = combined.slice(NONCE_SIZE);
  const aad = authContext ? buildMessageAad(authContext) : undefined;
  const plaintext = await aesGcmDecrypt(messageKey, nonce, ciphertext, aad);
  return bytesToString(plaintext);
}
