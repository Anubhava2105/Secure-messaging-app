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
  addGroupMember as apiAddGroupMember,
  createGroup as apiCreateGroup,
  findUserByUsername,
  findUserById,
  getPreKeyBundle,
  listGroups,
  removeGroupMember as apiRemoveGroupMember,
} from "../services/api";
import type { GroupInfoDTO } from "../services/api";
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
  ensureSessionForOutgoing,
  handleIncomingHandshake,
} from "../services/HandshakeManager";
import {
  ensureContactTrustFromBundle,
  markContactTrusted,
} from "../services/TrustManager";
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
  addGroup: (groupName: string, usernames: string[]) => Promise<boolean>;
  addGroupMember: (groupId: string, username: string) => Promise<boolean>;
  removeGroupMember: (groupId: string, userId: string) => Promise<boolean>;
  connectionStatus: "connected" | "disconnected" | "connecting";
  typingUsers: Set<string>;
  sendTypingIndicator: () => void;
  sendReadReceipt: (messageId: string, senderId: string) => void;
}

const MessengerContext = createContext<MessengerContextType | undefined>(
  undefined,
);
const ACTIVE_CONVERSATION_PREFIX = "securemsg.activeConversation.";
const LEGACY_DEMO_CONTACT_USERNAMES = new Set(["kenny", "bob", "alice"]);

function isPlaceholderDirectUsername(contact: {
  id: string;
  username: string;
  kind?: "direct" | "group";
}): boolean {
  if (contact.kind === "group") return false;

  const trimmed = contact.username.trim();
  if (!trimmed) return true;
  if (trimmed === contact.id) return true;

  return /^User-[A-Za-z0-9]{8,}$/.test(trimmed);
}

function activeConversationKey(userId: string): string {
  return `${ACTIVE_CONVERSATION_PREFIX}${userId}`;
}

function isGroupContact(contact: Contact | null): boolean {
  return Boolean(contact?.kind === "group");
}

function resolveConversationId(
  message: Message,
  currentUserId?: string,
): string {
  if (message.conversationId && message.conversationId.length > 0) {
    return message.conversationId;
  }
  if (message.groupId && message.groupId.length > 0) {
    return message.groupId;
  }
  if (currentUserId && message.senderId === currentUserId) {
    return message.recipientId;
  }
  return message.senderId;
}

function uniqueIds(values: string[] | undefined): string[] {
  if (!values) return [];
  return Array.from(new Set(values.filter(Boolean)));
}

function resolveGroupMessageStatus(
  message: Message,
  currentUserId: string,
  deliveredByUserIds: string[],
  readByUserIds: string[],
): Message["status"] {
  const recipients = uniqueIds(message.groupMemberIds).filter(
    (id) => id !== currentUserId,
  );

  const readCount = readByUserIds.filter((id) =>
    recipients.includes(id),
  ).length;
  const deliveredCount = deliveredByUserIds.filter((id) =>
    recipients.includes(id),
  ).length;

  if (recipients.length > 0 && readCount >= recipients.length) {
    return "read";
  }
  if (recipients.length > 0 && deliveredCount >= recipients.length) {
    return "delivered";
  }
  return "sent";
}

function applyGroupReceipt(
  message: Message,
  currentUserId: string,
  senderId: string,
  receiptType: "read" | "delivered",
): Message {
  const deliveredBy = uniqueIds([
    ...(message.deliveredByUserIds ?? []),
    senderId,
  ]);
  const readBy =
    receiptType === "read"
      ? uniqueIds([...(message.readByUserIds ?? []), senderId])
      : uniqueIds(message.readByUserIds);

  const status = resolveGroupMessageStatus(
    message,
    currentUserId,
    deliveredBy,
    readBy,
  );

  if (receiptType === "read") {
    return {
      ...message,
      readByUserIds: readBy,
      deliveredByUserIds: deliveredBy,
      status,
    };
  }

  return {
    ...message,
    deliveredByUserIds: deliveredBy,
    status,
  };
}

export const MessengerProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const { user, isAuthenticated } = useAuth();
  const [contacts, setContacts] = useState<Contact[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [activeContact, setActiveContact] = useState<Contact | null>(null);
  const [typingUsers, setTypingUsers] = useState<Set<string>>(new Set());
  const typingTimers = React.useRef<Map<string, ReturnType<typeof setTimeout>>>(
    new Map(),
  );
  const pendingHandshakeByPeer = React.useRef<Map<string, string>>(new Map());
  const retryCountByMessage = React.useRef<Map<string, number>>(new Map());
  const sendRef = React.useRef<(data: string) => void>(() => {});

  const setContactTrustInMemory = useCallback(
    (
      contactId: string,
      trustState: "trusted" | "unverified" | "changed",
      trustWarning?: string,
    ) => {
      setContacts((prev) =>
        prev.map((contact) =>
          contact.id === contactId
            ? {
                ...contact,
                trustState,
                trustWarning,
              }
            : contact,
        ),
      );
      setActiveContact((prev) =>
        prev && prev.id === contactId
          ? {
              ...prev,
              trustState,
              trustWarning,
            }
          : prev,
      );
    },
    [],
  );

  const upsertGroupContact = useCallback((group: GroupInfoDTO) => {
    const groupContact: Contact = {
      id: group.groupId,
      username: group.name,
      kind: "group",
      ownerId: group.ownerId,
      membershipCommitment: group.membershipCommitment,
      memberIds: uniqueIds(group.memberUserIds),
      status: "online",
      publicKeyEcc: new Uint8Array(),
      publicKeyPqc: new Uint8Array(),
    };

    setContacts((prevContacts) => {
      const existing = prevContacts.find((c) => c.id === group.groupId);
      if (!existing) {
        return [...prevContacts, groupContact];
      }

      return prevContacts.map((c) =>
        c.id === group.groupId
          ? {
              ...c,
              username: groupContact.username,
              kind: "group",
              ownerId: groupContact.ownerId,
              membershipCommitment: groupContact.membershipCommitment,
              memberIds: groupContact.memberIds,
            }
          : c,
      );
    });

    getKeyStore()
      .storeContact({
        id: group.groupId,
        username: group.name,
        kind: "group",
        ownerId: group.ownerId,
        membershipCommitment: group.membershipCommitment,
        memberIds: uniqueIds(group.memberUserIds),
        status: "online",
        trustState: undefined,
        trustWarning: undefined,
        trustUpdatedAt: Date.now(),
      })
      .catch(console.error);
  }, []);

  // ===== Auto-add Contact Helper =====
  const autoAddContact = useCallback((senderId: string) => {
    setContacts((prevContacts) => {
      const exists = prevContacts.some((c) => c.id === senderId);
      if (!exists) {
        console.log("[Messenger] Auto-adding sender as contact:", senderId);
        const newContact: Contact = {
          id: senderId,
          username: `User-${senderId.slice(0, 8)}`,
          kind: "direct",
          status: "online",
          publicKeyEcc: new Uint8Array(),
          publicKeyPqc: new Uint8Array(),
          trustState: "unverified",
          trustWarning:
            "Trust-on-first-use: verify this contact identity out-of-band.",
        };

        // Persist and async lookup of real username
        const store = getKeyStore();
        store.storeContact({
          id: senderId,
          username: newContact.username,
          kind: "direct",
          status: "online",
          trustState: newContact.trustState,
          trustWarning: newContact.trustWarning,
          trustUpdatedAt: Date.now(),
        });

        findUserById(senderId).then((userInfo) => {
          if (userInfo) {
            setContacts((prev) =>
              prev.map((c) =>
                c.id === senderId ? { ...c, username: userInfo.username } : c,
              ),
            );
            store.getContact(senderId).then((existing) => {
              store.storeContact({
                id: senderId,
                username: userInfo.username,
                kind: "direct",
                status: "online",
                trustState: existing?.trustState,
                trustWarning: existing?.trustWarning,
                trustUpdatedAt: existing?.trustUpdatedAt,
                identityKeyEccFingerprint: existing?.identityKeyEccFingerprint,
                identityKeyPqcFingerprint: existing?.identityKeyPqcFingerprint,
                signingKeyFingerprint: existing?.signingKeyFingerprint,
                lastSeen: existing?.lastSeen,
              });
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
      forceSessionReset = false,
      groupMeta?: {
        groupId: string;
        groupName: string;
        groupMemberIds: string[];
        groupEventType: "group_message";
        groupMembershipCommitment?: string;
      },
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
        recipientId,
        {
          // If we're resetting after peer-side decrypt failure, prefer a
          // three-DH handshake (without one-time prekey) for compatibility
          // with stale server-side one-time prekey inventories.
          disableOneTimePrekey: forceSessionReset,
        },
      );
      if (!sessionContext) {
        throw new Error("Failed to establish secure session");
      }

      const handshakeData = hadExistingSession
        ? undefined
        : (pendingHandshakeByPeer.current.get(recipientId) ??
          sessionContext.handshakeData);

      if (hadExistingSession) {
        pendingHandshakeByPeer.current.delete(recipientId);
      }

      let sendContext:
        | {
            messageKey: Uint8Array;
            messageNumber: number;
            ratchetPublicKey?: Uint8Array;
          }
        | undefined;

      try {
        sendContext = await nextSendMessageKeyWithNumber(recipientId);
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        const sessionStateLikelyCorrupted =
          /Invalid public key size|Invalid .*key size|operation-specific reason|Data provided to an operation does not meet requirements/i.test(
            reason,
          );

        if (sessionStateLikelyCorrupted && !forceSessionReset) {
          console.warn(
            "[Messenger] Outbound session state invalid; recreating secure session",
            reason,
          );
          await transmitOutboundMessage(
            content,
            recipientId,
            messageId,
            timestamp,
            true,
            groupMeta,
          );
          return;
        }

        throw error;
      }

      const {
        messageKey: sendMessageKey,
        messageNumber,
        ratchetPublicKey,
      } = sendContext;
      const encryptedBlob = await encryptMessage(content, sendMessageKey, {
        messageId,
        senderId: user.id,
        recipientId,
        groupId: groupMeta?.groupId,
        groupEventType: groupMeta?.groupEventType,
        groupMembershipCommitment: groupMeta?.groupMembershipCommitment,
      });

      const relayMessage: WsOutgoingMessage = {
        type: "send",
        messageId,
        recipientId,
        groupId: groupMeta?.groupId,
        groupName: groupMeta?.groupName,
        groupMemberIds: groupMeta?.groupMemberIds,
        groupEventType: groupMeta?.groupEventType,
        groupMembershipCommitment: groupMeta?.groupMembershipCommitment,
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
    [user],
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
              m.recipientId === msg.senderId,
          );

          if (!failed) {
            return;
          }

          // ACK from relay means queued/forwarded, not decrypt-successful.
          // Allow one repair retry for messages that are still sending or sent.
          if (failed.status !== "sending" && failed.status !== "sent") {
            return;
          }

          const currentRetries =
            retryCountByMessage.current.get(failed.id) ?? 0;
          if (currentRetries >= 1) {
            setMessages((prev) =>
              prev.map((m) =>
                m.id === failed.id &&
                (m.status === "sending" || m.status === "sent")
                  ? { ...m, status: "error" }
                  : m,
              ),
            );
            return;
          }

          retryCountByMessage.current.set(failed.id, currentRetries + 1);
          setMessages((prev) =>
            prev.map((m) =>
              m.id === failed.id &&
              (m.status === "sending" || m.status === "sent")
                ? { ...m, status: "sending" }
                : m,
            ),
          );

          try {
            await transmitOutboundMessage(
              failed.content,
              failed.recipientId,
              failed.id,
              failed.timestamp,
              true,
            );
          } catch (err) {
            console.error(
              "[Messenger] Retry after decrypt-failed failed:",
              err,
            );
            setMessages((prev) =>
              prev.map((m) =>
                m.id === failed.id &&
                (m.status === "sending" || m.status === "sent")
                  ? { ...m, status: "error" }
                  : m,
              ),
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
                : m,
            ),
          );
        }
        return;
      }

      if (msg.type === "ack") {
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId && (!user || m.senderId === user.id)
              ? { ...m, status: "sent" }
              : m,
          ),
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
          }, 3000),
        );
        return;
      }

      // Handle read receipt
      if (msg.type === "read" && msg.messageId) {
        retryCountByMessage.current.delete(msg.messageId);
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId
              ? m.groupId && user && msg.senderId
                ? applyGroupReceipt(m, user.id, msg.senderId, "read")
                : { ...m, status: "read" }
              : m,
          ),
        );
        return;
      }

      // Handle delivered receipt
      if (msg.type === "delivered" && msg.messageId) {
        retryCountByMessage.current.delete(msg.messageId);
        setMessages((prev) =>
          prev.map((m) =>
            m.id === msg.messageId
              ? m.groupId && user && msg.senderId
                ? applyGroupReceipt(m, user.id, msg.senderId, "delivered")
                : { ...m, status: "delivered" }
              : m,
          ),
        );
        return;
      }

      // Handle presence updates
      if (msg.type === "presence" && msg.senderId && msg.status) {
        setContacts((prev) =>
          prev.map((c) =>
            c.id === msg.senderId ? { ...c, status: msg.status! } : c,
          ),
        );
        return;
      }

      // Handle incoming encrypted message
      if (msg.type === "send" && msg.senderId && msg.encryptedBlob) {
        if (user && msg.senderId === user.id) {
          // Ignore self-loop frames defensively.
          return;
        }

        // Ensure sender appears in contact list even if handshake processing
        // fails and returns early.
        if (user && msg.senderId) {
          autoAddContact(msg.senderId);
        }

        const incomingConversationId = msg.groupId ?? msg.senderId;

        if (msg.groupId && user) {
          const groupName =
            msg.groupName?.trim() || `Group ${msg.groupId.slice(-6)}`;
          const mergedMembers = Array.from(
            new Set([...(msg.groupMemberIds ?? []), user.id, msg.senderId]),
          );

          const groupContact: Contact = {
            id: msg.groupId,
            username: groupName,
            kind: "group",
            membershipCommitment: msg.groupMembershipCommitment,
            memberIds: mergedMembers,
            status: "online",
            publicKeyEcc: new Uint8Array(),
            publicKeyPqc: new Uint8Array(),
          };

          setContacts((prevContacts) => {
            const existing = prevContacts.find((c) => c.id === msg.groupId);
            if (!existing) {
              return [...prevContacts, groupContact];
            }

            return prevContacts.map((c) =>
              c.id === msg.groupId
                ? {
                    ...c,
                    username: groupName,
                    kind: "group",
                    membershipCommitment:
                      msg.groupMembershipCommitment ?? c.membershipCommitment,
                    memberIds: mergedMembers,
                  }
                : c,
            );
          });

          getKeyStore()
            .storeContact({
              id: msg.groupId,
              username: groupName,
              kind: "group",
              membershipCommitment: msg.groupMembershipCommitment,
              memberIds: mergedMembers,
              status: "online",
              trustState: undefined,
              trustWarning: undefined,
              trustUpdatedAt: Date.now(),
            })
            .catch(console.error);
        }

        let session = await getSessionAsync(msg.senderId);

        // Handle handshake messages (first message from a new peer)
        if (msg.handshakeData && user) {
          const establishedSession = await handleIncomingHandshake(
            user.id,
            msg.senderId,
            msg.handshakeData,
          );

          if (!establishedSession) {
            const trustRecord = await getKeyStore().getContact(msg.senderId);
            if (trustRecord?.trustState === "changed") {
              setContactTrustInMemory(
                msg.senderId,
                "changed",
                trustRecord.trustWarning,
              );
            }

            // Request peer-side session reset/retry.
            const failureNotice: WsOutgoingMessage = {
              type: "error",
              messageId: msg.messageId || generateRandomId(),
              recipientId: msg.senderId,
              error: "decrypt-failed",
              timestamp: Date.now(),
            };
            sendRef.current(JSON.stringify(failureNotice));
            pendingHandshakeByPeer.current.delete(msg.senderId);
            return;
          }

          session = establishedSession;

          // If peer already established the shared session, any locally pending
          // outbound handshake for the same peer is stale and must be discarded.
          pendingHandshakeByPeer.current.delete(msg.senderId);
        }

        if (!session) {
          console.warn(
            "[Messenger] No matching session for incoming message; requesting sender retry",
          );
          const failureNotice: WsOutgoingMessage = {
            type: "error",
            messageId: msg.messageId || generateRandomId(),
            recipientId: msg.senderId,
            error: "decrypt-failed",
            timestamp: Date.now(),
          };
          sendRef.current(JSON.stringify(failureNotice));
          return;
        }

        try {
          const recvMessageKey = await nextReceiveMessageKeyAt(
            msg.senderId,
            msg.messageNumber,
            msg.ratchetKeyEcc ? base64ToBytes(msg.ratchetKeyEcc) : undefined,
          );
          const decrypted = await decryptMessage(
            msg.encryptedBlob,
            recvMessageKey,
            {
              messageId: msg.messageId,
              senderId: msg.senderId,
              recipientId: user?.id || "",
              groupId: msg.groupId,
              groupEventType: msg.groupEventType,
              groupMembershipCommitment: msg.groupMembershipCommitment,
            },
          );
          const newMessage: Message = {
            id: msg.messageId || generateRandomId(),
            senderId: msg.senderId,
            recipientId: msg.groupId ?? (user?.id || ""),
            conversationId: incomingConversationId,
            groupId: msg.groupId,
            groupName: msg.groupName,
            groupMemberIds: msg.groupMemberIds,
            groupEventType: msg.groupEventType,
            groupMembershipCommitment: msg.groupMembershipCommitment,
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
            peerId: incomingConversationId,
            conversationId: incomingConversationId,
          };
          store.storeMessage(storedMsg).catch(console.error);

          // Delivery receipt acknowledges successful decrypt/persistence.
          const deliveredReceipt: WsOutgoingMessage = {
            type: "delivered",
            messageId: newMessage.id,
            recipientId: msg.senderId,
            timestamp: Date.now(),
          };
          sendRef.current(JSON.stringify(deliveredReceipt));

          // Auto-send read receipt if user is currently viewing this conversation.
          if (activeContact?.id === incomingConversationId) {
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
    [
      user,
      messages,
      autoAddContact,
      activeContact,
      transmitOutboundMessage,
      setContactTrustInMemory,
    ],
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

  useEffect(() => {
    if (!user) return;

    const key = activeConversationKey(user.id);
    if (!activeContact) {
      window.sessionStorage.removeItem(key);
      return;
    }

    window.sessionStorage.setItem(key, activeContact.id);
  }, [activeContact, user]);

  // Load contacts/messages from IndexedDB on mount
  useEffect(() => {
    if (!isAuthenticated || !user) return;
    const store = getKeyStore();
    store
      .getAllContacts()
      .then((storedContacts) => {
        const currentUsername = user.username.trim().toLowerCase();
        const shouldDropContact = (contact: {
          id: string;
          username: string;
          kind?: "direct" | "group";
        }) => {
          if (contact.id === user.id) return true;
          if (contact.kind === "group") return false;

          const normalizedName = contact.username.trim().toLowerCase();
          if (normalizedName === currentUsername) return true;
          if (LEGACY_DEMO_CONTACT_USERNAMES.has(normalizedName)) return true;
          return false;
        };

        const sanitizedContacts = storedContacts.filter(
          (contact) => !shouldDropContact(contact),
        );
        const removedContacts = storedContacts.filter(shouldDropContact);

        if (removedContacts.length > 0) {
          Promise.all(
            removedContacts.map((contact) =>
              store.deleteContact(contact.id).catch(console.error),
            ),
          ).catch(console.error);
        }

        if (sanitizedContacts.length > 0) {
          const hydratedContacts: Contact[] = sanitizedContacts.map((c) => ({
            id: c.id,
            username: c.username,
            kind: c.kind,
            ownerId: c.ownerId,
            membershipCommitment: c.membershipCommitment,
            memberIds: c.memberIds,
            status: c.status,
            publicKeyEcc: new Uint8Array(),
            publicKeyPqc: new Uint8Array(),
            trustState: c.trustState,
            trustWarning: c.trustWarning,
          }));

          setContacts((prev) => {
            const removedIds = new Set(removedContacts.map((c) => c.id));
            const base = prev.filter((entry) => {
              if (removedIds.has(entry.id)) return false;
              if (entry.id === user.id) return false;
              if (entry.kind === "group") return true;

              const normalizedName = entry.username.trim().toLowerCase();
              if (normalizedName === currentUsername) return false;
              if (LEGACY_DEMO_CONTACT_USERNAMES.has(normalizedName))
                return false;
              return true;
            });

            const byId = new Map(base.map((entry) => [entry.id, entry]));
            for (const contact of hydratedContacts) {
              const existing = byId.get(contact.id);
              if (!existing) {
                byId.set(contact.id, contact);
                continue;
              }

              byId.set(contact.id, {
                ...contact,
                publicKeyEcc:
                  existing.publicKeyEcc.length > 0
                    ? existing.publicKeyEcc
                    : contact.publicKeyEcc,
                publicKeyPqc:
                  existing.publicKeyPqc.length > 0
                    ? existing.publicKeyPqc
                    : contact.publicKeyPqc,
                status:
                  existing.status === "online" ? "online" : contact.status,
              });
            }

            return Array.from(byId.values());
          });

          const placeholderContacts = sanitizedContacts.filter(
            isPlaceholderDirectUsername,
          );

          if (placeholderContacts.length > 0) {
            Promise.all(
              placeholderContacts.map(async (contact) => {
                const userInfo = await findUserById(contact.id);
                return {
                  contactId: contact.id,
                  username: userInfo?.username?.trim() ?? "",
                };
              }),
            )
              .then((resolved) => {
                const validUpdates = resolved.filter(
                  (item) => item.username.length > 0,
                );
                if (validUpdates.length === 0) return;

                const updateMap = new Map(
                  validUpdates.map((item) => [item.contactId, item.username]),
                );

                setContacts((prev) =>
                  prev.map((contact) => {
                    const resolvedName = updateMap.get(contact.id);
                    if (!resolvedName) return contact;
                    if (contact.username === resolvedName) return contact;
                    return { ...contact, username: resolvedName };
                  }),
                );

                Promise.all(
                  validUpdates.map(async (item) => {
                    const existing = await store.getContact(item.contactId);
                    if (!existing) return;

                    await store.storeContact({
                      ...existing,
                      username: item.username,
                    });
                  }),
                ).catch(console.error);
              })
              .catch((error) => {
                console.error(
                  "[Messenger] Failed to resolve contact usernames:",
                  error,
                );
              });
          }
        } else if (removedContacts.length > 0) {
          const removedIds = new Set(removedContacts.map((c) => c.id));
          setContacts((prev) =>
            prev.filter((entry) => !removedIds.has(entry.id)),
          );
        }
      })
      .catch((error) => {
        console.error("[Messenger] Failed to load stored contacts:", error);
      });
    store
      .getAllMessages()
      .then((storedMessages) => {
        if (storedMessages.length > 0) {
          const hydratedMessages = storedMessages.map((m) => {
            const base: Message = {
              id: m.id,
              senderId: m.senderId,
              recipientId: m.recipientId,
              conversationId: m.conversationId,
              groupId: m.groupId,
              groupName: m.groupName,
              groupMemberIds: m.groupMemberIds,
              groupEventType: m.groupEventType,
              groupMembershipCommitment: m.groupMembershipCommitment,
              deliveredByUserIds: m.deliveredByUserIds,
              readByUserIds: m.readByUserIds,
              content: m.content,
              timestamp: m.timestamp,
              isPqcProtected: m.isPqcProtected,
              status: m.status === "sending" ? "error" : m.status,
            };

            return {
              ...base,
              conversationId: resolveConversationId(base, user.id),
            };
          });

          setMessages((prev) => {
            const byId = new Map(prev.map((entry) => [entry.id, entry]));
            for (const message of hydratedMessages) {
              if (!byId.has(message.id)) {
                byId.set(message.id, message);
              }
            }

            return Array.from(byId.values()).sort(
              (a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id),
            );
          });
        }
      })
      .catch((error) => {
        console.error("[Messenger] Failed to load stored messages:", error);
      });
  }, [isAuthenticated, user]);

  useEffect(() => {
    if (!activeContact) return;
    if (!contacts.some((contact) => contact.id === activeContact.id)) {
      setActiveContact(null);
    }
  }, [activeContact, contacts]);

  useEffect(() => {
    if (!user || activeContact || contacts.length === 0) return;

    const key = activeConversationKey(user.id);
    const storedId = window.sessionStorage.getItem(key);
    if (!storedId) return;

    const restored = contacts.find((contact) => contact.id === storedId);
    if (restored) {
      setActiveContact(restored);
    }
  }, [contacts, activeContact, user]);

  useEffect(() => {
    if (!isAuthenticated || !user) return;

    let disposed = false;
    const loadGroups = async () => {
      const groups = await listGroups();
      if (disposed) return;

      for (const group of groups) {
        upsertGroupContact(group);
      }
    };

    void loadGroups();
    return () => {
      disposed = true;
    };
  }, [isAuthenticated, upsertGroupContact, user]);

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

      const targetIsGroup = isGroupContact(activeContact);

      if (!targetIsGroup && activeContact.trustState === "changed") {
        window.alert(
          activeContact.trustWarning ??
            "Security warning: contact keys changed. Messaging is blocked until you re-verify the contact.",
        );
        return;
      }

      if (!targetIsGroup && activeContact.trustState === "unverified") {
        const confirmed = window.confirm(
          activeContact.trustWarning ??
            "This contact has not been fully verified yet. Continue sending?",
        );
        if (!confirmed) {
          return;
        }

        await markContactTrusted(activeContact.id, activeContact.username);
        setContactTrustInMemory(activeContact.id, "trusted", undefined);
      }

      if (!targetIsGroup && activeContact.id === user.id) {
        console.warn("[Messenger] Blocking self-message");
        return;
      }

      if (connectionStatus !== "connected") {
        console.warn("[Messenger] Cannot send while disconnected");
        return;
      }

      const messageId = generateRandomId();
      const timestamp = Date.now();
      const conversationId = activeContact.id;

      const groupMemberIds = targetIsGroup
        ? Array.from(new Set([...(activeContact.memberIds ?? []), user.id]))
        : undefined;

      const groupRecipients = targetIsGroup
        ? (groupMemberIds?.filter((memberId) => memberId !== user.id) ?? [])
        : [];

      if (targetIsGroup && groupRecipients.length === 0) {
        window.alert(
          "Group has no other members. Add participants before sending messages.",
        );
        return;
      }

      // Optimistic update
      const newMessage: Message = {
        id: messageId,
        senderId: user.id,
        recipientId: conversationId,
        conversationId,
        groupId: targetIsGroup ? activeContact.id : undefined,
        groupName: targetIsGroup ? activeContact.username : undefined,
        groupMemberIds,
        groupEventType: targetIsGroup ? "group_message" : undefined,
        groupMembershipCommitment: targetIsGroup
          ? activeContact.membershipCommitment
          : undefined,
        deliveredByUserIds: targetIsGroup ? [] : undefined,
        readByUserIds: targetIsGroup ? [] : undefined,
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
        peerId: conversationId,
        conversationId,
      };
      store.storeMessage(storedMsg).catch(console.error);

      try {
        retryCountByMessage.current.set(messageId, 0);

        if (targetIsGroup) {
          const results = await Promise.allSettled(
            groupRecipients.map((recipientId) =>
              transmitOutboundMessage(
                content,
                recipientId,
                messageId,
                timestamp,
                false,
                {
                  groupId: activeContact.id,
                  groupName: activeContact.username,
                  groupMemberIds: groupMemberIds ?? [],
                  groupEventType: "group_message",
                  groupMembershipCommitment: activeContact.membershipCommitment,
                },
              ),
            ),
          );

          const hasFailures = results.some(
            (result) => result.status === "rejected",
          );
          if (hasFailures) {
            throw new Error("One or more group recipients failed");
          }

          setMessages((prev) =>
            prev.map((m) =>
              m.id === messageId && m.status === "sending"
                ? { ...m, status: "sent" }
                : m,
            ),
          );
          return;
        }

        await transmitOutboundMessage(
          content,
          activeContact.id,
          messageId,
          timestamp,
        );
      } catch (err) {
        console.error("[Messenger] Failed to send message:", err);

        setMessages((prev) =>
          prev.map((m) => (m.id === messageId ? { ...m, status: "error" } : m)),
        );
      }
    },
    [
      activeContact,
      user,
      connectionStatus,
      transmitOutboundMessage,
      setContactTrustInMemory,
    ],
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
      if (!bundle) {
        console.warn("[Messenger] Failed to fetch prekey bundle:", username);
        return false;
      }

      const trust = await ensureContactTrustFromBundle(
        userInfo.userId,
        bundle,
        userInfo.username,
      );

      if (!trust.trusted) {
        window.alert(
          trust.reason ??
            "Security warning: contact keys changed. Contact not added.",
        );
        return false;
      }

      const storedContact = await getKeyStore().getContact(userInfo.userId);

      const newContact: Contact = {
        id: userInfo.userId,
        username: userInfo.username,
        kind: "direct",
        status: "offline",
        publicKeyEcc: base64ToBytes(bundle.identityKeyEccPub),
        publicKeyPqc: base64ToBytes(bundle.identityKeyPqcPub),
        trustState: storedContact?.trustState ?? "trusted",
        trustWarning: storedContact?.trustWarning,
      };

      setContacts((prev) => [...prev, newContact]);

      // Persist contact to IndexedDB
      const store = getKeyStore();
      store
        .storeContact({
          id: newContact.id,
          username: newContact.username,
          kind: "direct",
          status: "offline",
          identityKeyEccFingerprint: storedContact?.identityKeyEccFingerprint,
          identityKeyPqcFingerprint: storedContact?.identityKeyPqcFingerprint,
          signingKeyFingerprint: storedContact?.signingKeyFingerprint,
          trustState: newContact.trustState,
          trustWarning: newContact.trustWarning,
          trustUpdatedAt: storedContact?.trustUpdatedAt ?? Date.now(),
        })
        .catch(console.error);

      console.log("[Messenger] Contact added:", username);
      return true;
    },
    [contacts, user],
  );

  // ===== Add Group =====
  const addGroup = useCallback(
    async (groupName: string, usernames: string[]): Promise<boolean> => {
      if (!user) return false;

      const normalizedName = groupName.trim();
      if (!normalizedName) {
        return false;
      }

      const candidateUsernames = Array.from(
        new Set(
          usernames
            .map((value) => value.trim())
            .filter(Boolean)
            .filter(
              (value) => value.toLowerCase() !== user.username.toLowerCase(),
            ),
        ),
      );

      if (candidateUsernames.length < 2) {
        return false;
      }

      const resolvedUsers = await Promise.all(
        candidateUsernames.map((username) => findUserByUsername(username)),
      );

      const validMembers = resolvedUsers
        .filter((entry): entry is NonNullable<typeof entry> => Boolean(entry))
        .filter((entry) => entry.userId !== user.id);

      if (validMembers.length < 2) {
        return false;
      }

      const memberIds = Array.from(
        new Set([user.id, ...validMembers.map((entry) => entry.userId)]),
      );

      const created = await apiCreateGroup(
        normalizedName,
        memberIds.filter((memberId) => memberId !== user.id),
      );
      if (!created) {
        return false;
      }

      upsertGroupContact(created);
      setActiveContact({
        id: created.groupId,
        username: created.name,
        kind: "group",
        ownerId: created.ownerId,
        membershipCommitment: created.membershipCommitment,
        memberIds: uniqueIds(created.memberUserIds),
        status: "online",
        publicKeyEcc: new Uint8Array(),
        publicKeyPqc: new Uint8Array(),
      });

      return true;
    },
    [user, upsertGroupContact],
  );

  const addGroupMember = useCallback(
    async (groupId: string, username: string): Promise<boolean> => {
      if (!user) return false;

      const normalizedUsername = username.trim();
      if (!normalizedUsername) return false;

      if (normalizedUsername.toLowerCase() === user.username.toLowerCase()) {
        return false;
      }

      const target = await findUserByUsername(normalizedUsername);
      if (!target) return false;

      const updated = await apiAddGroupMember(groupId, target.userId);
      if (!updated) return false;

      upsertGroupContact(updated);
      if (activeContact?.id === groupId) {
        setActiveContact((prev) =>
          prev && prev.id === groupId
            ? {
                ...prev,
                ownerId: updated.ownerId,
                membershipCommitment: updated.membershipCommitment,
                memberIds: uniqueIds(updated.memberUserIds),
              }
            : prev,
        );
      }
      return true;
    },
    [activeContact?.id, upsertGroupContact, user],
  );

  const removeGroupMember = useCallback(
    async (groupId: string, userId: string): Promise<boolean> => {
      if (!user) return false;

      const updated = await apiRemoveGroupMember(groupId, userId);
      if (!updated) {
        return false;
      }

      const stillMember = updated.memberUserIds.includes(user.id);
      if (!stillMember) {
        setContacts((prev) => prev.filter((contact) => contact.id !== groupId));
        if (activeContact?.id === groupId) {
          setActiveContact(null);
        }
        await getKeyStore().deleteContact(groupId).catch(console.error);
        return true;
      }

      upsertGroupContact(updated);
      if (activeContact?.id === groupId) {
        setActiveContact((prev) =>
          prev && prev.id === groupId
            ? {
                ...prev,
                ownerId: updated.ownerId,
                membershipCommitment: updated.membershipCommitment,
                memberIds: uniqueIds(updated.memberUserIds),
              }
            : prev,
        );
      }
      return true;
    },
    [activeContact?.id, upsertGroupContact, user],
  );

  // ===== Typing Indicator =====
  const sendTypingIndicator = useCallback(() => {
    if (!activeContact || !user) return;

    if (isGroupContact(activeContact)) {
      const recipients = (activeContact.memberIds ?? []).filter(
        (memberId) => memberId !== user.id,
      );

      for (const recipientId of recipients) {
        const msg: WsOutgoingMessage = {
          type: "typing",
          messageId: "",
          recipientId,
          groupId: activeContact.id,
          groupName: activeContact.username,
          groupMemberIds: activeContact.memberIds,
        };
        send(JSON.stringify(msg));
      }
      return;
    }

    const msg: WsOutgoingMessage = {
      type: "typing",
      messageId: "",
      recipientId: activeContact.id,
    };
    send(JSON.stringify(msg));
  }, [activeContact, send, user]);

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
    [send],
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
        addGroup,
        addGroupMember,
        removeGroupMember,
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
