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
  getSession,
  saveSession,
  clearAllSessions,
} from "../services/SessionManager";
import { base64ToBytes } from "../crypto/utils/encoding";
import { useWebSocket } from "../hooks/useWebSocket";
import { encryptMessage, decryptMessage } from "../utils/messageEncryption";
import { createDevSession } from "../utils/devSession";

// ===== Context Types =====
interface MessengerContextType {
  contacts: Contact[];
  messages: Message[];
  activeContact: Contact | null;
  setActiveContact: (contact: Contact | null) => void;
  sendMessage: (content: string) => Promise<void>;
  addContact: (username: string) => Promise<boolean>;
  connectionStatus: "connected" | "disconnected" | "connecting";
}

const MessengerContext = createContext<MessengerContextType | undefined>(
  undefined,
);

export const MessengerProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { user, isAuthenticated } = useAuth();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeContact, setActiveContact] = useState<Contact | null>(null);

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

        // Async lookup of real username
        findUserById(senderId).then((userInfo) => {
          if (userInfo) {
            setContacts((prev) =>
              prev.map((c) =>
                c.id === senderId ? { ...c, username: userInfo.username } : c,
              ),
            );
          }
        });

        return [...prevContacts, newContact];
      }
      return prevContacts;
    });
  }, []);

  // ===== Incoming Message Handler =====
  const handleIncomingMessage = useCallback(
    async (msg: WsIncomingMessage) => {
      console.log("[Messenger] Incoming message:", msg.type);

      if (msg.type === "error") {
        console.error("[Messenger] Server error:", msg.error);
        return;
      }

      if (msg.type === "ack") {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId ? { ...m, status: "sent" } : m,
          ),
        );
        return;
      }

      // Handle incoming encrypted message
      if (msg.type === "send" && msg.senderId && msg.encryptedBlob) {
        let session = getSession(msg.senderId);

        // Auto-create session for unknown sender (DEV mode)
        if (!session && user) {
          console.log(
            "[Messenger] Auto-creating session for sender:",
            msg.senderId,
          );
          session = await createDevSession(user.id, msg.senderId);
          saveSession(msg.senderId, session);
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
          const decrypted = await decryptMessage(msg.encryptedBlob, session);
          const newMessage: Message = {
            id: msg.messageId || generateRandomId(),
            senderId: msg.senderId,
            recipientId: user?.id || "",
            content: decrypted,
            timestamp: msg.timestamp || Date.now(),
            isPqcProtected: true,
            status: "delivered",
          };
          setMessages((prev) => [...prev, newMessage]);
        } catch (err) {
          console.error("[Messenger] Decryption failed:", err);
        }
      }
    },
    [user, autoAddContact],
  );

  // ===== WebSocket Connection =====
  const { connectionStatus, send } = useWebSocket({
    userId: isAuthenticated ? user?.id : undefined,
    onMessage: handleIncomingMessage,
    autoConnect: isAuthenticated,
  });

  // Cleanup sessions on unmount
  useEffect(() => {
    return () => {
      clearAllSessions();
    };
  }, []);

  // ===== Send Message =====
  const sendMessage = useCallback(
    async (content: string) => {
      if (!activeContact || !user) return;

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

      // Get or create session
      let session = getSession(activeContact.id);
      if (!session) {
        console.warn("[Messenger] Creating dev-mode session");
        session = await createDevSession(user.id, activeContact.id);
        saveSession(activeContact.id, session);
      }

      try {
        const encryptedBlob = await encryptMessage(content, session);

        const relayMessage: WsOutgoingMessage = {
          type: "send",
          messageId,
          recipientId: activeContact.id,
          encryptedBlob,
          timestamp,
        };

        send(JSON.stringify(relayMessage));
      } catch (err) {
        console.error("[Messenger] Failed to send message:", err);
        setMessages((prev) =>
          prev.map((m) => (m.id === messageId ? { ...m, status: "error" } : m)),
        );
      }
    },
    [activeContact, user, send],
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
      console.log("[Messenger] Contact added:", username);
      return true;
    },
    [contacts],
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
      }}
    >
      {children}
    </MessengerContext.Provider>
  );
};

export const useMessenger = () => {
  const context = useContext(MessengerContext);
  if (context === undefined) {
    throw new Error("useMessenger must be used within a MessengerProvider");
  }
  return context;
};
