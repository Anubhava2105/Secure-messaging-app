/**
 * WebSocket connection hook for browser and Electron.
 * Handles connection lifecycle and message routing.
 */

import { useCallback, useRef, useEffect, useState } from "react";
import { getWsUrl } from "../constants";
import { getAuthToken } from "../services/api";
import type { WsIncomingMessage } from "../types/wsTypes";

// Extend Window interface for Electron API
declare global {
  interface Window {
    electronAPI?: {
      connectRelay: (
        url: string,
        token: string,
      ) => Promise<{ success: boolean; error?: string }>;
      getRuntimeConfig?: () => Promise<{
        relayOrigin: string;
        apiBaseUrl: string;
        wsUrl: string;
      }>;
      sendMessage: (data: string) => Promise<boolean>;
      disconnectRelay: () => Promise<{ success: boolean }>;
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
  const outboxRef = useRef<string[]>([]);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectAttempt = useRef(0);
  const MAX_RECONNECT_DELAY = 30000;
  const MAX_OUTBOX_SIZE = 200;
  const isElectron =
    typeof window !== "undefined" && window.electronAPI !== undefined;

  const queueMessage = useCallback((data: string) => {
    if (outboxRef.current.length >= MAX_OUTBOX_SIZE) {
      outboxRef.current.shift();
    }
    outboxRef.current.push(data);
  }, []);

  const flushOutbox = useCallback(async () => {
    if (outboxRef.current.length === 0) return;

    if (isElectron) {
      const remaining: string[] = [];
      for (const msg of outboxRef.current) {
        try {
          const ok = await window.electronAPI!.sendMessage(msg);
          if (!ok) {
            remaining.push(msg);
          }
        } catch {
          remaining.push(msg);
        }
      }
      outboxRef.current = remaining;
      return;
    }

    const ws = wsRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN) return;

    while (outboxRef.current.length > 0) {
      const msg = outboxRef.current[0];
      try {
        ws.send(msg);
        outboxRef.current.shift();
      } catch {
        break;
      }
    }
  }, [isElectron]);

  // Use a ref to always access the latest onMessage callback
  const onMessageRef = useRef(onMessage);
  useEffect(() => {
    onMessageRef.current = onMessage;
  }, [onMessage]);

  const connectViaBrowserRef = useRef<(() => Promise<void>) | null>(null);

  // Browser WebSocket connection
  const connectViaBrowser = useCallback(async () => {
    if (!userId) return;
    setConnectionStatus("connecting");

    const token = getAuthToken();
    if (!token) {
      console.error("[WebSocket] No auth token available");
      setConnectionStatus("disconnected");
      throw new Error("No auth token");
    }

    const wsUrl = await getWsUrl();

    return new Promise<void>((resolve, reject) => {
      try {
        if (
          wsRef.current &&
          (wsRef.current.readyState === WebSocket.OPEN ||
            wsRef.current.readyState === WebSocket.CONNECTING)
        ) {
          try {
            wsRef.current.close(1000, "Replacing stale socket");
          } catch {
            // ignore
          }
        }

        const ws = new WebSocket(wsUrl, [`auth.${token}`]);
        wsRef.current = ws;

        ws.onopen = () => {
          if (wsRef.current !== ws) {
            resolve();
            return;
          }
          console.log("[WebSocket] Connected");
          setConnectionStatus("connected");
          reconnectAttempt.current = 0; // Reset backoff on success
          void flushOutbox();
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
          if (wsRef.current !== ws) {
            return;
          }
          console.log("[WebSocket] Closed:", event.code, event.reason);
          setConnectionStatus("disconnected");
          wsRef.current = null;

          // Auto-reconnect unless clean close (code 1000)
          if (event.code !== 1000 && userId && autoConnect) {
            const delay = Math.min(
              1000 * Math.pow(2, reconnectAttempt.current),
              MAX_RECONNECT_DELAY,
            );
            console.log(`[WebSocket] Reconnecting in ${delay}ms...`);
            reconnectTimer.current = setTimeout(() => {
              reconnectAttempt.current++;
              // Use queueMicrotask to access connect after it's declared
              queueMicrotask(() => {
                connectViaBrowserRef.current?.().catch(console.error);
              });
            }, delay);
          }
        };

        ws.onerror = (error) => {
          if (wsRef.current !== ws) {
            reject(error);
            return;
          }
          console.error("[WebSocket] Error:", error);
          setConnectionStatus("disconnected");
          reject(error);
        };
      } catch (err) {
        setConnectionStatus("disconnected");
        reject(err);
      }
    });
  }, [userId, autoConnect, flushOutbox]);

  useEffect(() => {
    connectViaBrowserRef.current = connectViaBrowser;
  }, [connectViaBrowser]);

  // Electron IPC connection
  const connectViaElectron = useCallback(async () => {
    if (!userId) return;
    setConnectionStatus("connecting");

    try {
      const token = getAuthToken();
      if (!token) {
        setConnectionStatus("disconnected");
        console.error("[WebSocket] No auth token available");
        return;
      }
      const wsUrl = await getWsUrl();
      const res = await window.electronAPI!.connectRelay(wsUrl, token);
      if (res.success) {
        setConnectionStatus("connected");
        await flushOutbox();
      } else {
        setConnectionStatus("disconnected");
        console.error("[WebSocket] Electron connection failed:", res.error);
      }
    } catch (err) {
      setConnectionStatus("disconnected");
      console.error("[WebSocket] Electron error:", err);
    }
  }, [userId, flushOutbox]);

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
    // Cancel any pending reconnect
    if (reconnectTimer.current) {
      clearTimeout(reconnectTimer.current);
      reconnectTimer.current = null;
    }
    reconnectAttempt.current = 0;

    if (isElectron && window.electronAPI) {
      window.electronAPI.disconnectRelay().catch(() => {
        // ignore best-effort disconnect failures
      });
    }

    if (wsRef.current) {
      wsRef.current.close(1000, "User disconnect");
      wsRef.current = null;
    }
    setConnectionStatus("disconnected");
  }, [isElectron]);

  // Send function
  const send = useCallback(
    (data: string) => {
      if (isElectron) {
        window
          .electronAPI!.sendMessage(data)
          .then((ok) => {
            if (!ok) {
              queueMessage(data);
            }
          })
          .catch(() => {
            queueMessage(data);
          });
      } else if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
        try {
          wsRef.current.send(data);
        } catch {
          queueMessage(data);
        }
      } else {
        queueMessage(data);
      }
    },
    [isElectron, queueMessage],
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

  // Handle Electron connection closed events.
  useEffect(() => {
    if (!isElectron || !window.electronAPI) return;

    const unsubscribe = window.electronAPI.onConnectionClosed(() => {
      setConnectionStatus("disconnected");

      if (!userId) return;

      const delay = Math.min(
        1000 * Math.pow(2, reconnectAttempt.current),
        MAX_RECONNECT_DELAY,
      );

      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current);
      }

      reconnectTimer.current = setTimeout(() => {
        reconnectAttempt.current += 1;
        void connect().catch(() => {
          // retry continues on next close signal
        });
      }, delay);
    });

    return unsubscribe;
  }, [isElectron, userId, connect]);

  return {
    connectionStatus,
    send,
    connect,
    disconnect,
    isElectron,
  };
}
