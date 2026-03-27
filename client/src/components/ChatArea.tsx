/**
 * Chat Area Component.
 * Displays messages and input for the active conversation.
 */

import React, { useState } from "react";
import { Shield, XCircle } from "lucide-react";
import type { Message, Contact } from "../types";

interface ChatAreaProps {
  activeContact: Contact;
  messages: Message[];
  currentUserId: string | undefined;
  onSendMessage: (content: string) => Promise<void>;
  onOpenSecurityDetails: () => void;
}

const ChatArea: React.FC<ChatAreaProps> = ({
  activeContact,
  messages,
  currentUserId,
  onSendMessage,
  onOpenSecurityDetails,
}) => {
  const [inputText, setInputText] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputText.trim()) return;

    await onSendMessage(inputText);
    setInputText("");
  };

  // Filter messages for this conversation
  const activeMessages = messages.filter(
    (m) =>
      m.recipientId === activeContact.id || m.senderId === activeContact.id,
  );

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
                {msg.status === "error" && (
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
      </section>

      <footer className="input-area">
        <form className="input-container" onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Type a secure message..."
            value={inputText}
            onChange={(e) => setInputText(e.target.value)}
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
