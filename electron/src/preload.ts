/**
 * Electron Preload Script
 *
 * SECURITY: This script bridges the isolated renderer and main process.
 *
 * IMPORTANT:
 * - Only expose the absolute minimum API surface
 * - Never expose Node.js modules or filesystem access
 * - Validate all inputs before sending to main process
 * - Only pass serializable data across the bridge
 */

import { contextBridge, ipcRenderer, IpcRendererEvent } from "electron";

/**
 * Secure API exposed to renderer via window.electronAPI
 */
const electronAPI = {
  // ==================
  // App Information
  // ==================

  /**
   * Get application version.
   */
  getAppVersion: (): Promise<string> => {
    return ipcRenderer.invoke("get-app-version");
  },

  // ==================
  // WebSocket Relay
  // ==================

  /**
   * Connect to the relay server.
   * @param url - WebSocket URL (validated in main process)
   * @param token - Authentication token
   */
  connectRelay: (
    url: string,
    token: string
  ): Promise<{ success: boolean; error?: string }> => {
    // Input validation
    if (typeof url !== "string" || typeof token !== "string") {
      return Promise.resolve({ success: false, error: "Invalid parameters" });
    }

    // Only allow WebSocket URLs
    if (!url.startsWith("ws://") && !url.startsWith("wss://")) {
      return Promise.resolve({
        success: false,
        error: "Invalid WebSocket URL",
      });
    }

    return ipcRenderer.invoke("connect-relay", url, token);
  },

  /**
   * Send a message via WebSocket.
   * @param data - JSON string to send (encrypted blob from crypto module)
   */
  sendMessage: (data: string): Promise<boolean> => {
    if (typeof data !== "string") {
      return Promise.resolve(false);
    }

    // Limit message size to prevent DoS
    if (data.length > 1024 * 1024) {
      // 1MB limit
      return Promise.resolve(false);
    }

    return ipcRenderer.invoke("send-ws-message", data);
  },

  /**
   * Disconnect from relay server.
   */
  disconnectRelay: (): Promise<{ success: boolean }> => {
    return ipcRenderer.invoke("disconnect-relay");
  },

  /**
   * Register callback for incoming WebSocket messages.
   * @param callback - Function to call with message data
   * @returns Cleanup function to unregister
   */
  onMessage: (callback: (data: string) => void): (() => void) => {
    const handler = (_event: IpcRendererEvent, data: string) => {
      callback(data);
    };

    ipcRenderer.on("ws-message", handler);

    return () => {
      ipcRenderer.removeListener("ws-message", handler);
    };
  },

  /**
   * Register callback for WebSocket close events.
   * @param callback - Function to call with close info
   * @returns Cleanup function to unregister
   */
  onConnectionClosed: (
    callback: (info: { code: number; reason: string }) => void
  ): (() => void) => {
    const handler = (
      _event: IpcRendererEvent,
      info: { code: number; reason: string }
    ) => {
      callback(info);
    };

    ipcRenderer.on("ws-closed", handler);

    return () => {
      ipcRenderer.removeListener("ws-closed", handler);
    };
  },

  // ==================
  // UI Utilities
  // ==================

  /**
   * Show a native message dialog.
   */
  showMessage: (options: {
    type: "none" | "info" | "error" | "question" | "warning";
    title: string;
    message: string;
    buttons?: string[];
  }): Promise<number> => {
    // Validate options
    if (
      !options ||
      typeof options.title !== "string" ||
      typeof options.message !== "string"
    ) {
      return Promise.resolve(-1);
    }

    return ipcRenderer.invoke("show-message", {
      type: options.type ?? "info",
      title: options.title.slice(0, 100), // Limit length
      message: options.message.slice(0, 1000), // Limit length
      buttons: options.buttons?.slice(0, 5), // Limit buttons
    });
  },
};

// Expose API to renderer
contextBridge.exposeInMainWorld("electronAPI", electronAPI);

// Type declaration for use in renderer
export type ElectronAPI = typeof electronAPI;
