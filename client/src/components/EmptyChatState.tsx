/**
 * Empty Chat State Component.
 * Displayed when no contact is selected.
 */

import React from "react";
import { Atom } from "lucide-react";

interface EmptyChatStateProps {
  onAddContact: () => void;
}

const EmptyChatState: React.FC<EmptyChatStateProps> = ({ onAddContact }) => {
  return (
    <div className="no-chat-selected">
      <div className="logo-placeholder">
        <Atom size={64} />
      </div>
      <h2>Universal Forward Secrecy</h2>
      <p>
        Select a contact or add a new one to start a post-quantum protected
        conversation.
      </p>
      <button className="btn-primary" onClick={onAddContact}>
        + Add Contact
      </button>
    </div>
  );
};

export default EmptyChatState;
