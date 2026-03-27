/**
 * WebSocket connection hook for browser and Electron.
 * Handles connection lifecycle and message routing.
 */

import { useCallback, useRef, useEffect, useState } from "react";
import { WS_URL } from "../constants";
import type { WsIncomingMessage } from "../types/wsTypes";

// Extend Window interface for Electron API
declare global {
  interface Window {
    electronAPI?: {
      connectRelay: (
        url: string,
        token: string,
      ) => Promise<{ success: boolean; error?: string }>;
      sendMessage: (data: string) => Promise<boolean>;
      onMessage: (callback: (data: string) => void) => () => void;
      onConnectionClosed: (
        callback: (info: { code: number; reason: string }) => void,
      ) => () => void;
    };
  }
}

export type ConnectionStatus = "connected" | "disconnected" | "connecting";

interface UseWebSocketOptions {
  userId: string | undefined;
  onMessage: (msg: WsIncomingMessage) => void;
  autoConnect?: boolean;
}

interface UseWebSocketReturn {
  connectionStatus: ConnectionStatus;
  send: (data: string) => void;
  connect: () => Promise<void>;
  disconnect: () => void;
  isElectron: boolean;
}

/**
 * Hook for managing WebSocket connections.
 * Automatically handles browser WebSocket and Electron IPC.
 */
export function useWebSocket({
  userId,
  onMessage,
  autoConnect = true,
}: UseWebSocketOptions): UseWebSocketReturn {
  const [connectionStatus, setConnectionStatus] =
    useState<ConnectionStatus>("disconnected");
  const wsRef = useRef<WebSocket | null>(null);
  const isElectron =
    typeof window !== "undefined" && window.electronAPI !== undefined;

  // Use a ref to always access the latest onMessage callback
  const onMessageRef = useRef(onMessage);
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  // Browser WebSocket connection
  const connectViaBrowser = useCallback(async () => {
    if (!userId) return;
    setConnectionStatus("connecting");

    return new Promise<void>((resolve, reject) => {
      try {
        const wsUrl = `${WS_URL}?userId=${encodeURIComponent(userId)}`;
        const ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log("[WebSocket] Connected");
          setConnectionStatus("connected");
          wsRef.current = ws;
          resolve();
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data) as WsIncomingMessage;
            // Use ref to always call the latest callback
            onMessageRef.current(data);
          } catch (err) {
            console.error("[WebSocket] Failed to parse message:", err);
          }
        };

        ws.onclose = (event) => {
          console.log("[WebSocket] Closed:", event.code, event.reason);
          setConnectionStatus("disconnected");
          wsRef.current = null;
        };

        ws.onerror = (error) => {
          console.error("[WebSocket] Error:", error);
          setConnectionStatus("disconnected");
          reject(error);
        };
      } catch (err) {
        setConnectionStatus("disconnected");
        reject(err);
      }
    });
  }, [userId]);

  // Electron IPC connection
  const connectViaElectron = useCallback(async () => {
    if (!userId) return;
    setConnectionStatus("connecting");

    try {
      const res = await window.electronAPI!.connectRelay(
        WS_URL,
        `placeholder-token-${userId}`,
      );
      if (res.success) {
        setConnectionStatus("connected");
      } else {
        setConnectionStatus("disconnected");
        console.error("[WebSocket] Electron connection failed:", res.error);
      }
    } catch (err) {
      setConnectionStatus("disconnected");
      console.error("[WebSocket] Electron error:", err);
    }
  }, [userId]);

  // Main connect function
  const connect = useCallback(async () => {
    if (isElectron) {
      await connectViaElectron();
    } else {
      await connectViaBrowser();
    }
  }, [isElectron, connectViaElectron, connectViaBrowser]);

  // Disconnect function
  const disconnect = useCallback(() => {
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }
    setConnectionStatus("disconnected");
  }, []);

  // Send function
  const send = useCallback(
    (data: string) => {
      if (isElectron) {
        window.electronAPI!.sendMessage(data);
      } else if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        wsRef.current.send(data);
      } else {
        throw new Error("WebSocket not connected");
      }
    },
    [isElectron],
  );

  // Auto-connect on mount (deferred to avoid synchronous setState)
  useEffect(() => {
    if (autoConnect && userId) {
      // Defer connection to avoid synchronous setState in effect body
      queueMicrotask(() => {
        connect();
      });
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, userId, connect, disconnect]);

  // Handle Electron messages
  useEffect(() => {
    if (!isElectron || connectionStatus !== "connected") return;

    const unsubscribe = window.electronAPI!.onMessage((data) => {
      try {
        const parsed = JSON.parse(data) as WsIncomingMessage;
        // Use ref to always call the latest callback
        onMessageRef.current(parsed);
      } catch (err) {
        console.error("[WebSocket] Failed to handle Electron message:", err);
      }
    });

    return unsubscribe;
  }, [connectionStatus, isElectron]);

  return {
    connectionStatus,
    send,
    connect,
    disconnect,
    isElectron,
  };
}
