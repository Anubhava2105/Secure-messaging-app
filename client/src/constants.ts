/**
 * Application-wide constants.
 */

export interface RuntimeConfig {
  relayOrigin: string;
  apiBaseUrl: string;
  wsUrl: string;
}

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

function normalizeUrl(value: string): string {
  return value.trim().replace(/\/+$/, "");
}

const browserHttpsOrigin =
  typeof window !== "undefined"
    ? `${window.location.protocol}//${window.location.host}`
    : "";

const secureRelayOrigin = isSecureContextBrowser
  ? normalizeHttpOrigin(browserHttpsOrigin)
  : normalizeHttpOrigin(configuredRelayOrigin);

const defaultRuntimeConfig: RuntimeConfig = {
  relayOrigin: secureRelayOrigin,
  apiBaseUrl:
    import.meta.env.VITE_API_BASE_URL ??
    (isDev ? "http://localhost:3000/api/v1" : `${secureRelayOrigin}/api/v1`),
  wsUrl:
    import.meta.env.VITE_WS_URL ??
    (isDev ? "ws://localhost:3000/ws" : `${toWsOrigin(secureRelayOrigin)}/ws`),
};

// WebSocket server URL (default; Electron runtime overrides at runtime)
export const WS_URL = defaultRuntimeConfig.wsUrl;

// API base URL (default; Electron runtime overrides at runtime)
export const API_BASE_URL = defaultRuntimeConfig.apiBaseUrl;

// AES-GCM nonce size in bytes
export const NONCE_SIZE = 12;

function sanitizeRuntimeConfig(
  config: RuntimeConfig | null | undefined,
): RuntimeConfig | null {
  if (!config) return null;
  if (
    typeof config.relayOrigin !== "string" ||
    typeof config.apiBaseUrl !== "string" ||
    typeof config.wsUrl !== "string"
  ) {
    return null;
  }

  const relayOrigin = normalizeHttpOrigin(config.relayOrigin);
  const apiBaseUrl = normalizeUrl(config.apiBaseUrl);
  const wsUrl = normalizeUrl(config.wsUrl);

  if (!/^https?:\/\//i.test(apiBaseUrl) || !/^wss?:\/\//i.test(wsUrl)) {
    return null;
  }

  return { relayOrigin, apiBaseUrl, wsUrl };
}

let runtimeConfigPromise: Promise<RuntimeConfig | null> | null = null;
let apiBaseUrlLogged = false;
let wsUrlLogged = false;

export async function getRuntimeConfig(): Promise<RuntimeConfig | null> {
  if (!runtimeConfigPromise) {
    if (
      typeof window === "undefined" ||
      !window.electronAPI?.getRuntimeConfig
    ) {
      runtimeConfigPromise = Promise.resolve(null);
    } else {
      runtimeConfigPromise = window.electronAPI
        .getRuntimeConfig()
        .then(sanitizeRuntimeConfig)
        .catch((error) => {
          console.warn(
            "[Config] Failed to load Electron runtime config",
            error,
          );
          return null;
        });
    }
  }

  return runtimeConfigPromise;
}

export async function getApiBaseUrl(): Promise<string> {
  const runtimeConfig = await getRuntimeConfig();
  const apiBaseUrl = runtimeConfig?.apiBaseUrl ?? API_BASE_URL;
  if (!apiBaseUrlLogged) {
    console.info(
      `[Config] API base URL: ${apiBaseUrl} (${runtimeConfig ? "electron" : "vite"})`,
    );
    apiBaseUrlLogged = true;
  }
  return apiBaseUrl;
}

export async function getWsUrl(): Promise<string> {
  const runtimeConfig = await getRuntimeConfig();
  const wsUrl = runtimeConfig?.wsUrl ?? WS_URL;
  if (!wsUrlLogged) {
    console.info(
      `[Config] WebSocket URL: ${wsUrl} (${runtimeConfig ? "electron" : "vite"})`,
    );
    wsUrlLogged = true;
  }
  return wsUrl;
}
