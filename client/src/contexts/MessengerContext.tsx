/**
 * Messenger Context.
 * Manages messaging state: contacts, messages, and WebSocket communication.
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";
import type { Message, Contact } from "../types";
import type { WsIncomingMessage, WsOutgoingMessage } from "../types/wsTypes";
import { useAuth } from "./AuthContext";
import { generateRandomId } from "../crypto/utils/random";
import {
  findUserByUsername,
  findUserById,
  getPreKeyBundle,
} from "../services/api";
import {
  getSessionAsync,
  deleteSession,
  clearAllSessions,
  nextSendMessageKeyWithNumber,
  nextReceiveMessageKeyAt,
} from "../services/SessionManager";
import { base64ToBytes, bytesToBase64 } from "../crypto/utils/encoding";
import { useWebSocket } from "../hooks/useWebSocket";
import { encryptMessage, decryptMessage } from "../utils/messageEncryption";
import {
  ensureSession,
  ensureSessionForOutgoing,
  handleIncomingHandshake,
} from "../services/HandshakeManager";
import { getKeyStore } from "../crypto/storage/keystore";
import type { StoredMessage } from "../crypto/storage/keystore";

// ===== Context Types =====
interface MessengerContextType {
  contacts: Contact[];
  messages: Message[];
  activeContact: Contact | null;
  setActiveContact: (contact: Contact | null) => void;
  sendMessage: (content: string) => Promise<void>;
  addContact: (username: string) => Promise<boolean>;
  connectionStatus: "connected" | "disconnected" | "connecting";
  typingUsers: Set<string>;
  sendTypingIndicator: () => void;
  sendReadReceipt: (messageId: string, senderId: string) => void;
}

const MessengerContext = createContext<MessengerContextType | undefined>(
  undefined
);

export const MessengerProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { user, isAuthenticated } = useAuth();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeContact, setActiveContact] = useState<Contact | null>(null);
  const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
  const typingTimers = React.useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map()
  );
  const pendingHandshakeByPeer = React.useRef<Map<string, string>>(new Map());
  const retryCountByMessage = React.useRef<Map<string, number>>(new Map());
  const sendRef = React.useRef<(data: string) => void>(() => {});

  // ===== Auto-add Contact Helper =====
  const autoAddContact = useCallback((senderId: string) => {
    setContacts((prevContacts) => {
      const exists = prevContacts.some((c) => c.id === senderId);
      if (!exists) {
        console.log("[Messenger] Auto-adding sender as contact:", senderId);
        const newContact: Contact = {
          id: senderId,
          username: `User-${senderId.slice(0, 8)}`,
          status: "online",
          publicKeyEcc: new Uint8Array(),
          publicKeyPqc: new Uint8Array(),
        };

        // Persist and async lookup of real username
        const store = getKeyStore();
        store.storeContact({
          id: senderId,
          username: newContact.username,
          status: "online",
        });

        findUserById(senderId).then((userInfo) => {
          if (userInfo) {
            setContacts((prev) =>
              prev.map((c) =>
                c.id === senderId ? { ...c, username: userInfo.username } : c
              )
            );
            store.storeContact({
              id: senderId,
              username: userInfo.username,
              status: "online",
            });
          }
        });

        return [...prevContacts, newContact];
      }
      return prevContacts;
    });
  }, []);

  const transmitOutboundMessage = useCallback(
    async (
      content: string,
      recipientId: string,
      messageId: string,
      timestamp: number,
      forceSessionReset = false
    ) => {
      if (!user) {
        throw new Error("Not authenticated");
      }

      if (forceSessionReset) {
        await deleteSession(recipientId);
        pendingHandshakeByPeer.current.delete(recipientId);
      }

      const hadExistingSession = !forceSessionReset
        ? Boolean(await getSessionAsync(recipientId))
        : false;

      // Get or create session. If it's a new session, attach handshake payload
      // to the first encrypted message for the peer to establish matching keys.
      const sessionContext = await ensureSessionForOutgoing(
        user.id,
        recipientId
      );
      if (!sessionContext) {
        throw new Error("Failed to establish secure session");
      }

      const handshakeData = hadExistingSession
        ? undefined
        : pendingHandshakeByPeer.current.get(recipientId) ??
          sessionContext.handshakeData;

      if (hadExistingSession) {
        pendingHandshakeByPeer.current.delete(recipientId);
      }

      const {
        messageKey: sendMessageKey,
        messageNumber,
        ratchetPublicKey,
      } = await nextSendMessageKeyWithNumber(recipientId);
      const encryptedBlob = await encryptMessage(content, sendMessageKey);

      const relayMessage: WsOutgoingMessage = {
        type: "send",
        messageId,
        recipientId,
        encryptedBlob,
        handshakeData,
        ratchetKeyEcc: ratchetPublicKey
          ? bytesToBase64(ratchetPublicKey)
          : undefined,
        messageNumber,
        timestamp,
      };

      sendRef.current(JSON.stringify(relayMessage));

      // Handshake payload is one-time. Once first message is sent, clear it.
      if (handshakeData) {
        pendingHandshakeByPeer.current.delete(recipientId);
      }
    },
    [user]
  );

  // ===== Incoming Message Handler =====
  const handleIncomingMessage = useCallback(
    async (msg: WsIncomingMessage) => {
      console.log("[Messenger] Incoming message:", msg.type);

      if (msg.type === "error") {
        console.error("[Messenger] Server error:", msg.error);

        // Peer-reported decrypt failure for our outbound message.
        if (
          user &&
          msg.senderId &&
          msg.senderId !== user.id &&
          msg.messageId &&
          msg.error === "decrypt-failed"
        ) {
          const failed = messages.find(
            (m) =>
              m.id === msg.messageId &&
              m.senderId === user.id &&
              m.recipientId === msg.senderId
          );

          if (!failed) {
            return;
          }

          // Ignore stale peer errors for messages that already advanced
          // to a terminal/success state (e.g. ACK arrived first).
          if (failed.status !== "sending") {
            return;
          }

          const currentRetries =
            retryCountByMessage.current.get(failed.id) ?? 0;
          if (currentRetries >= 1) {
            setMessages((prev) =>
              prev.map((m) =>
                m.id === failed.id && m.status === "sending"
                  ? { ...m, status: "error" }
                  : m
              )
            );
            return;
          }

          retryCountByMessage.current.set(failed.id, currentRetries + 1);
          setMessages((prev) =>
            prev.map((m) =>
              m.id === failed.id && m.status === "sending"
                ? { ...m, status: "sending" }
                : m
            )
          );

          try {
            await transmitOutboundMessage(
              failed.content,
              failed.recipientId,
              failed.id,
              failed.timestamp,
              true
            );
          } catch (err) {
            console.error(
              "[Messenger] Retry after decrypt-failed failed:",
              err
            );
            setMessages((prev) =>
              prev.map((m) =>
                m.id === failed.id && m.status === "sending"
                  ? { ...m, status: "error" }
                  : m
              )
            );
          }
          return;
        }

        // If this error corresponds to an optimistic outbound message,
        // mark it as failed instead of leaving it in "sending" state forever.
        if (msg.messageId) {
          setMessages((prev) =>
            prev.map((m) =>
              m.id === msg.messageId && m.status === "sending"
                ? { ...m, status: "error" }
                : m
            )
          );
        }
        return;
      }

      if (msg.type === "ack") {
        retryCountByMessage.current.delete(msg.messageId);
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId && (!user || m.senderId === user.id)
              ? { ...m, status: "sent" }
              : m
          )
        );
        return;
      }

      // Handle typing indicator
      if (msg.type === "typing" && msg.senderId) {
        setTypingUsers((prev) => {
          const next = new Set(prev);
          next.add(msg.senderId!);
          return next;
        });
        const existing = typingTimers.current.get(msg.senderId);
        if (existing) clearTimeout(existing);
        typingTimers.current.set(
          msg.senderId,
          setTimeout(() => {
            setTypingUsers((prev) => {
              const next = new Set(prev);
              next.delete(msg.senderId!);
              return next;
            });
          }, 3000)
        );
        return;
      }

      // Handle read receipt
      if (msg.type === "read" && msg.messageId) {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId ? { ...m, status: "read" } : m
          )
        );
        return;
      }

      // Handle delivered receipt
      if (msg.type === "delivered" && msg.messageId) {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId ? { ...m, status: "delivered" } : m
          )
        );
        return;
      }

      // Handle presence updates
      if (msg.type === "presence" && msg.senderId && msg.status) {
        setContacts((prev) =>
          prev.map((c) =>
            c.id === msg.senderId ? { ...c, status: msg.status! } : c
          )
        );
        return;
      }

      // Handle incoming encrypted message
      if (msg.type === "send" && msg.senderId && msg.encryptedBlob) {
        if (user && msg.senderId === user.id) {
          // Ignore self-loop frames defensively.
          return;
        }

        // Handle handshake messages (first message from a new peer)
        if (msg.handshakeData && user) {
          await handleIncomingHandshake(
            user.id,
            msg.senderId,
            msg.handshakeData
          );
          // If peer already established the shared session, any locally pending
          // outbound handshake for the same peer is stale and must be discarded.
          pendingHandshakeByPeer.current.delete(msg.senderId);
        }

        // Get or create session
        let session = await getSessionAsync(msg.senderId);
        if (!session && user) {
          session = await ensureSession(user.id, msg.senderId);
        }

        // Auto-add sender as contact
        if (user && msg.senderId) {
          autoAddContact(msg.senderId);
        }

        if (!session) {
          console.warn("[Messenger] No session for sender - giving up");
          return;
        }

        try {
          const recvMessageKey = await nextReceiveMessageKeyAt(
            msg.senderId,
            msg.messageNumber,
            msg.ratchetKeyEcc ? base64ToBytes(msg.ratchetKeyEcc) : undefined
          );
          const decrypted = await decryptMessage(
            msg.encryptedBlob,
            recvMessageKey
          );
          const newMessage: Message = {
            id: msg.messageId || generateRandomId(),
            senderId: msg.senderId,
            recipientId: user?.id || "",
            content: decrypted,
            timestamp: msg.timestamp || Date.now(),
            isPqcProtected: true,
            status: "delivered",
          };
          setMessages((prev) => {
            if (prev.some((m) => m.id === newMessage.id)) {
              return prev;
            }
            return [...prev, newMessage];
          });

          // Persist to IndexedDB
          const store = getKeyStore();
          const storedMsg: StoredMessage = {
            ...newMessage,
            peerId: msg.senderId,
          };
          store.storeMessage(storedMsg).catch(console.error);

          // Auto-send read receipt if user is currently viewing this conversation.
          if (activeContact?.id === msg.senderId) {
            const receipt: WsOutgoingMessage = {
              type: "read",
              messageId: newMessage.id,
              recipientId: msg.senderId,
              timestamp: Date.now(),
            };
            sendRef.current(JSON.stringify(receipt));
          }
        } catch (err) {
          console.error("[Messenger] Decryption failed:", err);

          // Notify sender to refresh their session and retry exactly once.
          const failureNotice: WsOutgoingMessage = {
            type: "error",
            messageId: msg.messageId || generateRandomId(),
            recipientId: msg.senderId,
            error: "decrypt-failed",
            timestamp: Date.now(),
          };
          sendRef.current(JSON.stringify(failureNotice));
        }
      }
    },
    [user, messages, autoAddContact, activeContact, transmitOutboundMessage]
  );

  // ===== WebSocket Connection =====
  const { connectionStatus, send } = useWebSocket({
    userId: isAuthenticated ? user?.id : undefined,
    onMessage: handleIncomingMessage,
    autoConnect: isAuthenticated,
  });

  useEffect(() => {
    sendRef.current = send;
  }, [send]);

  // Load contacts/messages from IndexedDB on mount
  useEffect(() => {
    if (!isAuthenticated || !user) return;
    const store = getKeyStore();
    store.getAllContacts().then((storedContacts) => {
      const sanitizedContacts = storedContacts.filter((c) => c.id !== user.id);

      // Cleanup legacy/invalid self-contact entries from prior builds.
      if (sanitizedContacts.length !== storedContacts.length) {
        store.deleteContact(user.id).catch(console.error);
      }

      if (sanitizedContacts.length > 0) {
        setContacts(
          sanitizedContacts.map((c) => ({
            id: c.id,
            username: c.username,
            status: c.status,
            publicKeyEcc: new Uint8Array(),
            publicKeyPqc: new Uint8Array(),
          }))
        );
      }
    });
    store.getAllMessages().then((storedMessages) => {
      if (storedMessages.length > 0) {
        setMessages(
          storedMessages.map((m) => ({
            id: m.id,
            senderId: m.senderId,
            recipientId: m.recipientId,
            content: m.content,
            timestamp: m.timestamp,
            isPqcProtected: m.isPqcProtected,
            status: m.status === "sending" ? "error" : m.status,
          }))
        );
      }
    });
  }, [isAuthenticated, user]);

  // Cleanup sessions on unmount
  useEffect(() => {
    return () => {
      clearAllSessions().catch(console.error);
    };
  }, []);

  // ===== Send Message =====
  const sendMessage = useCallback(
    async (content: string) => {
      if (!activeContact || !user || !content.trim()) return;

      if (activeContact.id === user.id) {
        console.warn("[Messenger] Blocking self-message");
        return;
      }

      if (connectionStatus !== "connected") {
        console.warn("[Messenger] Cannot send while disconnected");
        return;
      }

      const messageId = generateRandomId();
      const timestamp = Date.now();

      // Optimistic update
      const newMessage: Message = {
        id: messageId,
        senderId: user.id,
        recipientId: activeContact.id,
        content,
        timestamp,
        isPqcProtected: true,
        status: "sending",
      };
      setMessages((prev) => [...prev, newMessage]);

      // Persist to IndexedDB
      const store = getKeyStore();
      const storedMsg: StoredMessage = {
        ...newMessage,
        peerId: activeContact.id,
      };
      store.storeMessage(storedMsg).catch(console.error);
      try {
        retryCountByMessage.current.set(messageId, 0);
        await transmitOutboundMessage(
          content,
          activeContact.id,
          messageId,
          timestamp
        );
      } catch (err) {
        console.error("[Messenger] Failed to send message:", err);

        setMessages((prev) =>
          prev.map((m) => (m.id === messageId ? { ...m, status: "error" } : m))
        );
      }
    },
    [activeContact, user, connectionStatus, transmitOutboundMessage]
  );

  // ===== Add Contact =====
  const addContact = useCallback(
    async (username: string): Promise<boolean> => {
      if (!username.trim()) return false;

      console.log("[Messenger] Adding contact:", username);

      const userInfo = await findUserByUsername(username);
      if (!userInfo) {
        console.warn("[Messenger] User not found:", username);
        return false;
      }

      if (user && userInfo.userId === user.id) {
        console.warn("[Messenger] Cannot add yourself as contact");
        return false;
      }

      if (contacts.some((c) => c.id === userInfo.userId)) {
        console.log("[Messenger] Contact already exists:", username);
        return true;
      }

      const bundle = await getPreKeyBundle(userInfo.userId);

      const newContact: Contact = {
        id: userInfo.userId,
        username: userInfo.username,
        status: "offline",
        publicKeyEcc: bundle
          ? base64ToBytes(bundle.identityKeyEccPub)
          : new Uint8Array(),
        publicKeyPqc: bundle
          ? base64ToBytes(bundle.identityKeyPqcPub)
          : new Uint8Array(),
      };

      setContacts((prev) => [...prev, newContact]);

      // Persist contact to IndexedDB
      const store = getKeyStore();
      store
        .storeContact({
          id: newContact.id,
          username: newContact.username,
          status: "offline",
        })
        .catch(console.error);

      console.log("[Messenger] Contact added:", username);
      return true;
    },
    [contacts, user]
  );

  // ===== Typing Indicator =====
  const sendTypingIndicator = useCallback(() => {
    if (!activeContact) return;
    const msg: WsOutgoingMessage = {
      type: "typing",
      messageId: "",
      recipientId: activeContact.id,
    };
    send(JSON.stringify(msg));
  }, [activeContact, send]);

  // ===== Read Receipt =====
  const sendReadReceipt = useCallback(
    (messageId: string, senderId: string) => {
      const msg: WsOutgoingMessage = {
        type: "read",
        messageId,
        recipientId: senderId,
      };
      send(JSON.stringify(msg));
    },
    [send]
  );

  return (
    <MessengerContext.Provider
      value={{
        contacts,
        messages,
        activeContact,
        setActiveContact,
        sendMessage,
        addContact,
        connectionStatus,
        typingUsers,
        sendTypingIndicator,
        sendReadReceipt,
      }}
    >
      {children}
    </MessengerContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useMessenger = () => {
  const context = useContext(MessengerContext);
  if (context === undefined) {
    throw new Error("useMessenger must be used within a MessengerProvider");
  }
  return context;
};
