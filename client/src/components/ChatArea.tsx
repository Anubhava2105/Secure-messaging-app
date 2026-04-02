/**
 * Chat Area Component.
 * Displays messages and input for the active conversation.
 */

import React, { useState, useRef, useCallback } from "react";
import { Shield, XCircle, Check, CheckCheck } from "lucide-react";
import type { Message, Contact } from "../types";

interface ChatAreaProps {
  activeContact: Contact;
  messages: Message[];
  currentUserId: string | undefined;
  onSendMessage: (content: string) => Promise<void>;
  onOpenSecurityDetails: () => void;
  isContactTyping?: boolean;
  onTyping?: () => void;
}

const ChatArea: React.FC<ChatAreaProps> = ({
  activeContact,
  messages,
  currentUserId,
  onSendMessage,
  onOpenSecurityDetails,
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

  // Filter messages for this conversation
  const activeMessages = messages
    .filter(
      (m) =>
        m.recipientId === activeContact.id || m.senderId === activeContact.id
    )
    .sort((a, b) => a.timestamp - b.timestamp || a.id.localeCompare(b.id));

  return (
    <>
      <header className="chat-header">
        <div className="header-info">
          <h3>{activeContact.username}</h3>
          <p className="security-status">
            <span className="shield">
              <Shield size={16} />
            </span>
            Hybrid Protected Session • P-384 + ML-KEM-768
          </p>
        </div>
        <div className="header-actions">
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
              <div className="message-content">{msg.content}</div>
              <div className="message-meta">
                {new Date(msg.timestamp).toLocaleTimeString([], {
                  hour: "2-digit",
                  minute: "2-digit",
                })}
                {msg.isPqcProtected && " • ✓"}
                {msg.status === "sending" && " • Sending..."}
                {msg.status === "sent" && msg.senderId === currentUserId && (
                  <span> • <Check size={12} style={{ display: "inline", verticalAlign: "middle" }} /></span>
                )}
                {msg.status === "delivered" && msg.senderId === currentUserId && (
                  <span> • <CheckCheck size={12} style={{ display: "inline", verticalAlign: "middle" }} /></span>
                )}
                {msg.status === "read" && msg.senderId === currentUserId && (
                  <span> • <CheckCheck size={12} style={{ display: "inline", verticalAlign: "middle", color: "var(--success)" }} /></span>
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
              <span>•</span><span>•</span><span>•</span>
            </span>
            {activeContact.username} is typing...
          </div>
        )}
      </section>

      <footer className="input-area">
        <form className="input-container" onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Type a secure message..."
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
