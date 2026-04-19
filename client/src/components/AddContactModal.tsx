/**
 * Add Contact Modal Component.
 * Allows users to add new contacts by username.
 */

import React, { useState } from "react";
import { useAuth } from "../contexts/AuthContext";

interface AddContactModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAdd: (username: string) => Promise<boolean>;
  onAddGroup: (groupName: string, usernames: string[]) => Promise<boolean>;
}

const AddContactModal: React.FC<AddContactModalProps> = ({
  isOpen,
  onClose,
  onAdd,
  onAddGroup,
}) => {
  const { user } = useAuth();
  const [mode, setMode] = useState<"contact" | "group">("contact");
  const [username, setUsername] = useState("");
  const [groupName, setGroupName] = useState("");
  const [groupUsersInput, setGroupUsersInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleContactSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim()) return;

    if (user && username.trim().toLowerCase() === user.username.toLowerCase()) {
      setError("You cannot add yourself as a contact.");
      return;
    }

    setIsLoading(true);
    setError(null);

    const success = await onAdd(username.trim());
    setIsLoading(false);

    if (success) {
      setUsername("");
      onClose();
    } else {
      setError(
        "Contact could not be added. Confirm the username exists and that you are connected.",
      );
    }
  };

  const handleGroupSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    const normalizedGroupName = groupName.trim();
    const usernames = groupUsersInput
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean);
    const uniqueUsernames = Array.from(
      new Set(usernames.map((value) => value.toLowerCase())),
    );

    if (!normalizedGroupName) {
      setError("Group name is required.");
      return;
    }

    if (usernames.length < 2) {
      setError("Enter at least 2 usernames for a group.");
      return;
    }

    if (uniqueUsernames.length !== usernames.length) {
      setError("Remove duplicate usernames before creating the group.");
      return;
    }

    if (
      user &&
      usernames.some(
        (value) => value.toLowerCase() === user.username.toLowerCase(),
      )
    ) {
      setError("Do not include yourself in group member usernames.");
      return;
    }

    setIsLoading(true);
    setError(null);

    const success = await onAddGroup(normalizedGroupName, usernames);
    setIsLoading(false);

    if (success) {
      setGroupName("");
      setGroupUsersInput("");
      onClose();
    } else {
      setError(
        "Group creation failed. Verify each username exists and that at least two other members are valid.",
      );
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>{mode === "contact" ? "Add Contact" : "Create Group"}</h2>
        <div
          className="modal-mode-toggle"
          role="tablist"
          aria-label="Compose mode"
        >
          <button
            type="button"
            className={`btn-secondary ${mode === "contact" ? "active" : ""}`}
            onClick={() => {
              setMode("contact");
              setError(null);
            }}
            disabled={isLoading}
          >
            Contact
          </button>
          <button
            type="button"
            className={`btn-secondary ${mode === "group" ? "active" : ""}`}
            onClick={() => {
              setMode("group");
              setError(null);
            }}
            disabled={isLoading}
          >
            Group
          </button>
        </div>
        <p className="modal-description">
          {mode === "contact"
            ? "Enter the username of the person you want to message."
            : "Create a group by name and add at least 2 member usernames (comma separated)."}
        </p>

        <form
          onSubmit={
            mode === "contact" ? handleContactSubmit : handleGroupSubmit
          }
        >
          {mode === "contact" ? (
            <input
              type="text"
              placeholder="Username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isLoading}
              autoFocus
            />
          ) : (
            <>
              <input
                type="text"
                placeholder="Group name"
                value={groupName}
                onChange={(e) => setGroupName(e.target.value)}
                disabled={isLoading}
                autoFocus
              />
              <input
                type="text"
                placeholder="alice, bob, charlie"
                value={groupUsersInput}
                onChange={(e) => setGroupUsersInput(e.target.value)}
                disabled={isLoading}
              />
            </>
          )}
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
              disabled={
                isLoading ||
                (mode === "contact"
                  ? !username.trim()
                  : !groupName.trim() || !groupUsersInput.trim())
              }
            >
              {isLoading
                ? mode === "contact"
                  ? "Searching..."
                  : "Creating..."
                : mode === "contact"
                  ? "Add Contact"
                  : "Create Group"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default AddContactModal;
