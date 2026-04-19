import React, { useMemo, useState } from "react";
import type { Contact } from "../types";

interface GroupMembersModalProps {
  isOpen: boolean;
  onClose: () => void;
  group: Contact | null;
  contacts: Contact[];
  currentUserId?: string;
  onAddMember: (groupId: string, username: string) => Promise<boolean>;
  onRemoveMember: (groupId: string, userId: string) => Promise<boolean>;
}

const GroupMembersModal: React.FC<GroupMembersModalProps> = ({
  isOpen,
  onClose,
  group,
  contacts,
  currentUserId,
  onAddMember,
  onRemoveMember,
}) => {
  const [memberUsername, setMemberUsername] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const [removingUserId, setRemovingUserId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const memberIds = group?.memberIds ?? [];
  const isOwner = Boolean(group?.ownerId && group.ownerId === currentUserId);
  const canOwnerLeave = memberIds.length > 2;

  const memberRows = useMemo(
    () =>
      memberIds.map((memberId) => {
        const known = contacts.find((contact) => contact.id === memberId);
        return {
          userId: memberId,
          username: known?.username ?? `User-${memberId.slice(0, 8)}`,
          isOwner: group?.ownerId === memberId,
          isSelf: currentUserId === memberId,
        };
      }),
    [contacts, currentUserId, group?.ownerId, memberIds],
  );

  if (!isOpen || !group || group.kind !== "group") {
    return null;
  }

  const handleAddMember = async (event: React.FormEvent) => {
    event.preventDefault();

    const username = memberUsername.trim();
    if (!username) return;

    setIsAdding(true);
    setError(null);

    const success = await onAddMember(group.id, username);

    setIsAdding(false);
    if (success) {
      setMemberUsername("");
      return;
    }

    setError("Unable to add member. Confirm username and permissions.");
  };

  const handleRemoveMember = async (userId: string) => {
    const isSelf = userId === currentUserId;
    const isOwnerLeaving = isSelf && isOwner;

    if (isOwnerLeaving && !canOwnerLeave) {
      setError(
        "You cannot leave this group yet. Add one more member before ownership can transfer.",
      );
      return;
    }

    const confirmed = window.confirm(
      isOwnerLeaving
        ? "Leaving will transfer ownership to another member. Continue?"
        : isSelf
          ? "Leave this group?"
          : "Remove this member from the group?",
    );
    if (!confirmed) {
      return;
    }

    setRemovingUserId(userId);
    setError(null);

    const success = await onRemoveMember(group.id, userId);

    setRemovingUserId(null);
    if (!success) {
      setError(
        isOwnerLeaving
          ? "Could not leave group. Ensure at least two members remain after transfer."
          : "Member update failed. Check permissions and group state, then retry.",
      );
      return;
    }

    if (userId === currentUserId) {
      onClose();
    }
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content" onClick={(e) => e.stopPropagation()}>
        <h2>Manage Group Members</h2>
        <p className="modal-description">
          {group.username} • {Math.max(memberIds.length - 1, 0)} members
        </p>
        {isOwner && (
          <p className="group-owner-note">
            {canOwnerLeave
              ? "Leaving transfers ownership to another remaining member automatically."
              : "Add one more member before you can leave as owner."}
          </p>
        )}

        <div className="group-members-list">
          {memberRows.map((member) => {
            const canRemove = member.isOwner
              ? member.isSelf
              : isOwner || member.isSelf;
            const disableRemove =
              member.isOwner && member.isSelf && !canOwnerLeave;

            return (
              <div key={member.userId} className="group-member-row">
                <div>
                  <div className="group-member-name">{member.username}</div>
                  <div className="group-member-meta">
                    {member.isOwner
                      ? "Owner"
                      : member.isSelf
                        ? "You"
                        : "Member"}
                  </div>
                </div>
                {canRemove && (
                  <button
                    type="button"
                    className="btn-secondary"
                    disabled={removingUserId === member.userId || disableRemove}
                    onClick={() => {
                      void handleRemoveMember(member.userId);
                    }}
                  >
                    {removingUserId === member.userId
                      ? "Removing..."
                      : member.isSelf && member.isOwner
                        ? "Transfer & Leave"
                        : member.isSelf
                          ? "Leave"
                          : "Remove"}
                  </button>
                )}
              </div>
            );
          })}
        </div>

        {isOwner && (
          <form onSubmit={handleAddMember} className="group-member-add-form">
            <input
              type="text"
              placeholder="Username to add"
              value={memberUsername}
              onChange={(e) => setMemberUsername(e.target.value)}
              disabled={isAdding}
            />
            <button
              type="submit"
              className="btn-primary"
              disabled={isAdding || !memberUsername.trim()}
            >
              {isAdding ? "Adding..." : "Add Member"}
            </button>
          </form>
        )}

        {error && <p className="error-message">{error}</p>}

        <div className="modal-actions">
          <button type="button" className="btn-secondary" onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default GroupMembersModal;
