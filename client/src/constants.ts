/**
 * Application-wide constants.
 */

const isSecureContextBrowser =
  typeof window !== "undefined" && window.location.protocol === "https:";

const isDev = import.meta.env.DEV;

const configuredRelayOrigin =
  (import.meta.env.VITE_RELAY_ORIGIN as string | undefined)?.trim() ||
  "https://relay.securemsg.app";

function toWsOrigin(httpOrigin: string): string {
  return httpOrigin
    .replace(/^http:\/\//i, "ws://")
    .replace(/^https:\/\//i, "wss://");
}

function normalizeHttpOrigin(origin: string): string {
  const trimmed = origin.trim().replace(/\/+$/, "");
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  return `https://${trimmed}`;
}

const browserHttpsOrigin =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.host}`
    : "";

const secureRelayOrigin = isSecureContextBrowser
  ? normalizeHttpOrigin(browserHttpsOrigin)
  : normalizeHttpOrigin(configuredRelayOrigin);

// WebSocket server URL (override with VITE_WS_URL)
export const WS_URL =
  import.meta.env.VITE_WS_URL ??
  (isDev ? "ws://localhost:3000/ws" : `${toWsOrigin(secureRelayOrigin)}/ws`);

// AES-GCM nonce size in bytes
export const NONCE_SIZE = 12;

// API base URL (override with VITE_API_BASE_URL)
export const API_BASE_URL =
  import.meta.env.VITE_API_BASE_URL ??
  (isDev ? "http://localhost:3000/api/v1" : `${secureRelayOrigin}/api/v1`);
