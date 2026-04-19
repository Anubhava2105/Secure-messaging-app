/**
 * Sidebar Component.
 * Displays contacts list, user info, and navigation.
 */

import React from "react";
import type { Contact } from "../types";
import type { ConnectionStatus } from "../hooks/useWebSocket";

interface SidebarProps {
  username: string | undefined;
  connectionStatus: ConnectionStatus;
  contacts: Contact[];
  activeContact: Contact | null;
  onSelectContact: (contact: Contact) => void;
  onAddContact: () => void;
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({
  username,
  connectionStatus,
  contacts,
  activeContact,
  onSelectContact,
  onAddContact,
  onLogout,
}) => {
  return (
    <div className="sidebar">
      <div className="sidebar-header">
        <div className="brand">
          <h2 className="gradient-text">Cipher</h2>
          <span className="version">v0.1.0-alpha</span>
        </div>
        <div className="user-badge">
          <span className={`status-dot ${connectionStatus}`}></span>
          <span className="username">{username}</span>
        </div>
      </div>

      <div className="contacts-list">
        <div className="section-title">Active Chats</div>
        {contacts.length === 0 ? (
          <div className="empty-state">
            <p>No contacts yet.</p>
            <button className="btn-add-contact" onClick={onAddContact}>
              + Add your first contact
            </button>
          </div>
        ) : (
          contacts.map((contact) => (
            <div
              key={contact.id}
              className={`contact-item ${
                activeContact?.id === contact.id ? "active" : ""
              }`}
              onClick={() => onSelectContact(contact)}
            >
              <div className="avatar">{contact.username[0].toUpperCase()}</div>
              <div className="contact-info">
                <div className="contact-name">{contact.username}</div>
                <div className="last-message">
                  {contact.kind === "group"
                    ? `${Math.max((contact.memberIds?.length ?? 1) - 1, 0)} members`
                    : contact.trustState === "changed"
                      ? "Key mismatch detected"
                      : contact.trustState === "unverified"
                        ? "Identity not fully verified"
                        : "Protected session"}
                </div>
              </div>
              {contact.kind === "group" ? (
                <span className="pqc-badge">GROUP</span>
              ) : contact.trustState === "changed" ? (
                <span className="trust-badge trust-badge-alert">KEY ALERT</span>
              ) : contact.trustState === "unverified" ? (
                <span className="trust-badge trust-badge-warn">VERIFY</span>
              ) : null}
              {contact.publicKeyPqc.length > 0 &&
                contact.trustState !== "changed" && (
                  <span className="pqc-badge">PQC</span>
                )}
            </div>
          ))
        )}
      </div>

      <div className="sidebar-footer">
        <button className="btn-secondary" onClick={onAddContact}>
          + New Chat
        </button>
        <button className="btn-secondary" onClick={onLogout}>
          Logout
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
