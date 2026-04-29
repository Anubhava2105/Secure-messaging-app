/**
 * Electron Main Process
 *
 * SECURITY CONFIGURATION:
 * This file implements all security hardening for the Electron app.
 *
 * Key security measures:
 * 1. Context isolation: true
 * 2. Node integration: false (in renderer)
 * 3. Sandbox: true
 * 4. Strict CSP headers
 * 5. Disabled remote module
 * 6. Restricted navigation
 * 7. Minimal preload API surface
 */

import {
  app,
  BrowserWindow,
  ipcMain,
  session,
  shell,
  dialog,
  Event,
  WebContents,
  HeadersReceivedResponse,
  OnHeadersReceivedListenerDetails,
} from "electron";
import * as path from "path";
import { WebSocket } from "ws";

// Test-mode controls for running multiple isolated local Electron instances.
const allowMultiInstance = process.env.ALLOW_MULTI_INSTANCE === "true";
const userDataSuffix = (process.env.USER_DATA_SUFFIX ?? "").trim();

if (allowMultiInstance && userDataSuffix.length > 0) {
  const baseUserData = app.getPath("userData");
  app.setPath("userData", `${baseUserData}-${userDataSuffix}`);
}

if (!allowMultiInstance) {
  // Prevent multiple instances in normal mode.
  const gotTheLock = app.requestSingleInstanceLock();
  if (!gotTheLock) {
    app.quit();
  }
}

// Note: The remote module has been removed in Electron 14+
// Security is now handled via contextIsolation, nodeIntegration, and sandbox settings

// Store reference to main window
let mainWindow: BrowserWindow | null = null;

// WebSocket connection
let wsConnection: WebSocket | null = null;

const isDevelopment = process.env.NODE_ENV === "development";
const isPackaged = app.isPackaged;
const allowInsecureDevCerts = process.env.ALLOW_INSECURE_DEV_CERTS === "true";

type RuntimeConfig = {
  relayOrigin: string;
  apiBaseUrl: string;
  wsUrl: string;
};

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

function buildRuntimeConfig(): RuntimeConfig {
  const defaultRelayOrigin =
    isPackaged || isDevelopment
      ? "http://localhost:3000"
      : "https://relay.securemsg.app";
  const relayOrigin = normalizeHttpOrigin(
    process.env.ELECTRON_RELAY_ORIGIN ??
      process.env.RELAY_ORIGIN ??
      defaultRelayOrigin,
  );
  const wsOrigin = toWsOrigin(relayOrigin);

  return {
    relayOrigin,
    apiBaseUrl: `${relayOrigin}/api/v1`,
    wsUrl: `${wsOrigin}/ws`,
  };
}

const runtimeConfig = buildRuntimeConfig();
console.info("[Electron] Runtime config:", runtimeConfig);

/**
 * Create the main browser window with security hardening.
 */
function createWindow(): BrowserWindow {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    title: "Secure Messaging",

    webPreferences: {
      // ============================================
      // CRITICAL SECURITY SETTINGS - DO NOT CHANGE
      // ============================================

      // Disable Node.js integration in renderer
      nodeIntegration: false,

      // Disable Node.js in web workers
      nodeIntegrationInWorker: false,

      // Enable context isolation (renderer cannot access preload directly)
      contextIsolation: true,

      // Enable sandbox for additional isolation
      sandbox: true,

      // Enforce same-origin policy
      webSecurity: true,

      // Disable running insecure content
      allowRunningInsecureContent: false,

      // Disable experimental features
      experimentalFeatures: false,

      // Preload script path (minimal API surface)
      preload: path.join(__dirname, "preload.js"),

      // Disable spell checking to prevent data leakage
      spellcheck: false,
    },

    // Show after ready to prevent flash
    show: false,
  });

  // Show window when ready
  mainWindow.once("ready-to-show", () => {
    mainWindow?.show();
  });

  // Set Content Security Policy
  setContentSecurityPolicy(runtimeConfig);

  // Prevent new window creation
  mainWindow.webContents.setWindowOpenHandler(({ url }: { url: string }) => {
    // Allow opening external links in default browser
    if (url.startsWith("https://")) {
      shell.openExternal(url);
    }
    return { action: "deny" as const };
  });

  // Prevent navigation away from app
  mainWindow.webContents.on("will-navigate", (event: Event, url: string) => {
    const parsedUrl = new URL(url);

    // Allow navigation to app content only
    if (
      parsedUrl.protocol !== "file:" &&
      parsedUrl.host !== "localhost" &&
      !url.startsWith("http://localhost")
    ) {
      event.preventDefault();
      console.warn("Blocked navigation to:", url);
    }
  });

  // Prevent new webContents creation
  mainWindow.webContents.on("will-attach-webview", (event: Event) => {
    event.preventDefault();
    console.warn("Blocked webview attachment");
  });

  // Load the app
  if (isDevelopment) {
    // Development: load from Vite dev server
    mainWindow.loadURL("http://localhost:5173");
    mainWindow.webContents.openDevTools();
  } else {
    // Production: load from built files
    mainWindow.loadFile(path.join(__dirname, "../../client/dist/index.html"));
  }

  mainWindow.on("closed", () => {
    mainWindow = null;
    closeWebSocket();
  });

  return mainWindow;
}

/**
 * Set strict Content Security Policy.
 */
function setContentSecurityPolicy(config: RuntimeConfig): void {
  const apiOrigin = new URL(config.apiBaseUrl).origin;
  const wsOrigin = new URL(config.wsUrl).origin;
  const connectSources = Array.from(new Set(["'self'", apiOrigin, wsOrigin]));

  session.defaultSession.webRequest.onHeadersReceived(
    (
      details: OnHeadersReceivedListenerDetails,
      callback: (response: HeadersReceivedResponse) => void,
    ) => {
      callback({
        responseHeaders: {
          ...details.responseHeaders,
          "Content-Security-Policy": [
            [
              // Only allow resources from same origin
              "default-src 'self'",

              // Scripts: self + wasm for PQC crypto
              "script-src 'self' 'wasm-unsafe-eval'",

              // Styles: self + inline + Google Fonts CSS
              "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",

              // Style elements (explicit for Google Fonts)
              "style-src-elem 'self' 'unsafe-inline' https://fonts.googleapis.com",

              // Connect: self + configured relay WebSocket endpoint
              `connect-src ${connectSources.join(" ")}`,

              // Images: self + data URIs + blobs
              "img-src 'self' data: blob:",

              // Fonts: self + Google Fonts
              "font-src 'self' https://fonts.gstatic.com",

              // No plugins
              "object-src 'none'",

              // Base URI restriction
              "base-uri 'self'",

              // Form action restriction
              "form-action 'self'",

              // No framing
              "frame-ancestors 'none'",

              // Upgrade insecure requests only when relay is https
              !isDevelopment && config.relayOrigin.startsWith("https://")
                ? "upgrade-insecure-requests"
                : "",
            ]
              .filter(Boolean)
              .join("; "),
          ],
        },
      });
    },
  );
}

/**
 * Connect to WebSocket relay server.
 */
function connectWebSocket(url: string, token: string): Promise<void> {
  return new Promise((resolve, reject) => {
    if (wsConnection) {
      wsConnection.close();
    }

    wsConnection = new WebSocket(url, [`auth.${token}`]);

    wsConnection.on("open", () => {
      console.log("WebSocket connected");
      resolve();
    });

    wsConnection.on("message", (data: Buffer) => {
      // Forward message to renderer
      mainWindow?.webContents.send("ws-message", data.toString());
    });

    wsConnection.on("close", (code: number, reason: Buffer) => {
      console.log("WebSocket closed:", code, reason.toString());
      wsConnection = null;
      mainWindow?.webContents.send("ws-closed", {
        code,
        reason: reason.toString(),
      });
    });

    wsConnection.on("error", (error: Error) => {
      console.error("WebSocket error:", error.message);
      reject(error);
    });
  });
}

/**
 * Send message via WebSocket.
 */
function sendWebSocketMessage(data: string): boolean {
  if (!wsConnection || wsConnection.readyState !== WebSocket.OPEN) {
    return false;
  }
  wsConnection.send(data);
  return true;
}

/**
 * Close WebSocket connection.
 */
function closeWebSocket(): void {
  if (wsConnection) {
    wsConnection.close();
    wsConnection = null;
  }
}

// ==================
// IPC Handlers
// ==================

// Get app version
ipcMain.handle("get-app-version", () => {
  return app.getVersion();
});

// Get runtime config for renderer
ipcMain.handle("get-runtime-config", () => {
  return runtimeConfig;
});

// Connect to relay server
ipcMain.handle(
  "connect-relay",
  async (_event: Electron.IpcMainInvokeEvent, url: string, token: string) => {
    try {
      await connectWebSocket(url, token);
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  },
);

// Send WebSocket message
ipcMain.handle(
  "send-ws-message",
  (_event: Electron.IpcMainInvokeEvent, data: string) => {
    return sendWebSocketMessage(data);
  },
);

// Disconnect WebSocket
ipcMain.handle("disconnect-relay", () => {
  closeWebSocket();
  return { success: true };
});

// Show native message dialog (for errors, confirmations)
ipcMain.handle(
  "show-message",
  async (
    _event: Electron.IpcMainInvokeEvent,
    options: {
      type: "none" | "info" | "error" | "question" | "warning";
      title: string;
      message: string;
      buttons?: string[];
    },
  ) => {
    const result = await dialog.showMessageBox(mainWindow!, {
      type: options.type,
      title: options.title,
      message: options.message,
      buttons: options.buttons ?? ["OK"],
    });
    return result.response;
  },
);

// ==================
// App Lifecycle
// ==================

app.whenReady().then(() => {
  createWindow();

  app.on("activate", () => {
    // macOS: Re-create window when dock icon is clicked
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

app.on("window-all-closed", () => {
  // Quit on all platforms when windows are closed
  closeWebSocket();
  app.quit();
});

app.on("second-instance", () => {
  // Focus main window if user tries to open another instance
  if (mainWindow) {
    if (mainWindow.isMinimized()) {
      mainWindow.restore();
    }
    mainWindow.focus();
  }
});

// Security: Prevent certificate errors from being silently ignored
app.on(
  "certificate-error",
  (
    event: Event,
    _webContents: WebContents,
    _url: string,
    _error: string,
    _certificate: Electron.Certificate,
    callback: (isTrusted: boolean) => void,
  ) => {
    // Self-signed certificates are only allowed when explicitly opted in.
    if (isDevelopment && allowInsecureDevCerts) {
      event.preventDefault();
      callback(true);
    } else {
      // Reject invalid certificates by default in all other cases.
      callback(false);
    }
  },
);
