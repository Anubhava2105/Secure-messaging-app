/**
 * SQLite schema migration entrypoint.
 *
 * Running this script ensures the database exists and all
 * required schema updates are applied.
 */

import { store } from "./sqlite.js";

async function main(): Promise<void> {
  // Trigger store initialization and schema setup.
  // Querying basic state verifies DB connectivity.
  await store.userExists("__migration_probe__");
  console.log("[migrate] SQLite schema is up to date");
}

main().catch((err) => {
  console.error("[migrate] Migration failed:", err);
  process.exit(1);
});
