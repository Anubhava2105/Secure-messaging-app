/**
 * Application-wide constants.
 */

const isSecureContextBrowser =
  typeof window !== "undefined" && window.location.protocol === "https:";

const isDev = import.meta.env.DEV;

const defaultHost =
  typeof window !== "undefined" && window.location.hostname
    ? window.location.hostname
    : "localhost";

// WebSocket server URL (override with VITE_WS_URL)
export const WS_URL =
  import.meta.env.VITE_WS_URL ??
  (isDev
    ? "ws://localhost:3000/ws"
    : isSecureContextBrowser
    ? `wss://${defaultHost}:3000/ws`
    : `wss://${defaultHost}:3000/ws`);

// AES-GCM nonce size in bytes
export const NONCE_SIZE = 12;

// API base URL (override with VITE_API_BASE_URL)
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ??
  (isDev
    ? "http://localhost:3000/api/v1"
    : isSecureContextBrowser
    ? `https://${defaultHost}:3000/api/v1`
    : `https://${defaultHost}:3000/api/v1`);
