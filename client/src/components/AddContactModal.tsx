/**
 * Add Contact Modal Component.
 * Allows users to add new contacts by username.
 */

import React, { useState } from "react";

interface AddContactModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAdd: (username: string) => Promise<boolean>;
}

const AddContactModal: React.FC<AddContactModalProps> = ({
  isOpen,
  onClose,
  onAdd,
}) => {
  const [username, setUsername] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return;

    setIsLoading(true);
    setError(null);

    const success = await onAdd(username.trim());
    setIsLoading(false);

    if (success) {
      setUsername("");
      onClose();
    } else {
      setError("User not found. Please check the username.");
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Add Contact</h2>
        <p className="modal-description">
          Enter the username of the person you want to message.
        </p>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={isLoading}
            autoFocus
          />
          {error && <p className="error-message">{error}</p>}
          <div className="modal-actions">
            <button
              type="button"
              className="btn-secondary"
              onClick={onClose}
              disabled={isLoading}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={isLoading || !username.trim()}
            >
              {isLoading ? "Searching..." : "Add Contact"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddContactModal;
