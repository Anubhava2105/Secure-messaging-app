/**
 * Chat Area Component.
 * Displays messages and input for the active conversation.
 */

import React, { useState, useRef, useCallback } from "react";
import { Shield, XCircle, Check, CheckCheck } from "lucide-react";
import type { Message, Contact } from "../types";

interface ChatAreaProps {
  activeContact: Contact;
  contacts: Contact[];
  messages: Message[];
  currentUserId: string | undefined;
  onSendMessage: (content: string) => Promise<void>;
  onOpenSecurityDetails: () => void;
  onOpenGroupMembers?: () => void;
  isContactTyping?: boolean;
  onTyping?: () => void;
}

const ChatArea: React.FC<ChatAreaProps> = ({
  activeContact,
  contacts,
  messages,
  currentUserId,
  onSendMessage,
  onOpenSecurityDetails,
  onOpenGroupMembers,
  isContactTyping = false,
  onTyping,
}) => {
  const [inputText, setInputText] = useState("");
  const lastTypingTime = useRef<number>(0);

  const handleInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      setInputText(e.target.value);
      if (onTyping) {
        const now = Date.now();
        if (now - lastTypingTime.current > 2000) {
          onTyping();
          lastTypingTime.current = now;
        }
      }
    },
    [onTyping],
  );

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;

    await onSendMessage(inputText);
    setInputText("");
  };

  const resolveConversationId = (message: Message): string => {
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
  };

  const resolveSenderName = (senderId: string): string => {
    if (senderId === currentUserId) return "You";
    const contact = contacts.find((entry) => entry.id === senderId);
    return contact?.username ?? `User-${senderId.slice(0, 8)}`;
  };

  // Filter messages for this conversation
  const activeMessages = messages
    .filter((m) => resolveConversationId(m) === activeContact.id)
    .sort((a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id));

  const memberCount = activeContact.memberIds?.length ?? 0;

  const getGroupStatusSummary = (message: Message): string | null => {
    if (
      activeContact.kind !== "group" ||
      message.senderId !== currentUserId ||
      !message.groupMemberIds
    ) {
      return null;
    }

    const recipientIds = Array.from(
      new Set(message.groupMemberIds.filter((id) => id !== currentUserId)),
    );

    if (recipientIds.length === 0) {
      return " • No recipients";
    }

    const readIds = Array.from(new Set(message.readByUserIds ?? [])).filter(
      (id) => recipientIds.includes(id),
    );
    const deliveredIds = Array.from(
      new Set(message.deliveredByUserIds ?? []),
    ).filter((id) => recipientIds.includes(id));

    const deliveredOnlyIds = deliveredIds.filter((id) => !readIds.includes(id));
    const readNames = readIds.map(resolveSenderName);
    const deliveredNames = deliveredOnlyIds.map(resolveSenderName);

    const formatMemberList = (names: string[]): string => {
      if (names.length === 0) return "";
      if (names.length <= 2) return names.join(", ");
      return `${names.slice(0, 2).join(", ")} +${names.length - 2}`;
    };

    const segments: string[] = [];
    if (readIds.length > 0) {
      segments.push(
        `Read by ${formatMemberList(readNames)} (${readIds.length}/${recipientIds.length})`,
      );
    }
    if (deliveredOnlyIds.length > 0) {
      segments.push(
        `Delivered to ${formatMemberList(deliveredNames)} (${deliveredOnlyIds.length}/${recipientIds.length})`,
      );
    }

    if (segments.length === 0) {
      return ` • Awaiting delivery (0/${recipientIds.length})`;
    }

    return ` • ${segments.join(" • ")}`;
  };

  return (
    <>
      <header className="chat-header">
        <div className="header-info">
          <h3>
            {activeContact.username}
            {activeContact.kind === "group" ? " • Group" : ""}
          </h3>
          <p className="security-status">
            <span className="shield">
              <Shield size={16} />
            </span>
            {activeContact.kind === "group"
              ? `${Math.max(memberCount - 1, 0)} members • Context-bound E2EE fan-out`
              : "Hybrid Protected Session • P-384 + ML-KEM-768"}
          </p>
        </div>
        <div className="header-actions">
          {activeContact.kind === "group" && onOpenGroupMembers && (
            <button
              className="pqc-status-btn"
              title="Manage Group Members"
              onClick={onOpenGroupMembers}
            >
              Members
            </button>
          )}
          <button
            className="pqc-status-btn"
            title="View Security Details"
            onClick={onOpenSecurityDetails}
          >
            Quantum Safe
          </button>
        </div>
      </header>

      <section className="messages-container">
        {activeMessages.length === 0 ? (
          <div className="start-chat">
            <div className="shield-large">
              <Shield size={48} />
            </div>
            <p>
              Messaging with <strong>{activeContact.username}</strong> is
              secured with post-quantum cryptography.
            </p>
          </div>
        ) : (
          activeMessages.map((msg) => (
            <div
              key={msg.id}
              className={`message ${
                msg.senderId === currentUserId ? "sent" : "received"
              }`}
            >
              {activeContact.kind === "group" &&
                msg.senderId !== currentUserId && (
                  <div className="message-sender">
                    {resolveSenderName(msg.senderId)}
                  </div>
                )}
              <div className="message-content">{msg.content}</div>
              <div className="message-meta">
                {new Date(msg.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
                {msg.isPqcProtected && " • ✓"}
                {msg.status === "sending" && " • Sending..."}
                {getGroupStatusSummary(msg)}
                {msg.status === "sent" && msg.senderId === currentUserId && (
                  <span>
                    {" "}
                    •{" "}
                    <Check
                      size={12}
                      style={{ display: "inline", verticalAlign: "middle" }}
                    />
                  </span>
                )}
                {msg.status === "delivered" &&
                  msg.senderId === currentUserId && (
                    <span>
                      {" "}
                      •{" "}
                      <CheckCheck
                        size={12}
                        style={{ display: "inline", verticalAlign: "middle" }}
                      />
                    </span>
                  )}
                {msg.status === "read" && msg.senderId === currentUserId && (
                  <span>
                    {" "}
                    •{" "}
                    <CheckCheck
                      size={12}
                      style={{
                        display: "inline",
                        verticalAlign: "middle",
                        color: "var(--success)",
                      }}
                    />
                  </span>
                )}
                {msg.status === "error" && msg.senderId === currentUserId && (
                  <span>
                    {" "}
                    •{" "}
                    <XCircle
                      size={12}
                      style={{
                        display: "inline",
                        verticalAlign: "middle",
                      }}
                    />{" "}
                    Failed
                  </span>
                )}
              </div>
            </div>
          ))
        )}
        {isContactTyping && (
          <div className="typing-indicator">
            <span className="typing-dots">
              <span>•</span>
              <span>•</span>
              <span>•</span>
            </span>
            {activeContact.username} is typing...
          </div>
        )}
      </section>

      <footer className="input-area">
        <form className="input-container" onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder={
              activeContact.kind === "group"
                ? "Type a secure group message..."
                : "Type a secure message..."
            }
            value={inputText}
            onChange={handleInputChange}
          />
          <button
            type="submit"
            className="btn-send"
            disabled={!inputText.trim()}
          >
            Send
          </button>
        </form>
      </footer>
    </>
  );
};

export default ChatArea;
