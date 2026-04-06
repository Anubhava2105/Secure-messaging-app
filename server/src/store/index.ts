/**
 * Data store singleton export.
 * Now using persistent SQLite storage.
 *
 * SECURITY: Only stores public keys and encrypted blobs.
 * No private keys or plaintext messages are ever stored.
 */

export { store } from "./sqlite.js";

