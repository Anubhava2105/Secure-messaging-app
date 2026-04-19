export interface User {
  id: string;
  username: string;
  lastSeen?: number;
}

export interface Contact extends User {
  kind?: "direct" | "group";
  ownerId?: string;
  membershipCommitment?: string;
  publicKeyEcc: Uint8Array;
  publicKeyPqc: Uint8Array;
  status: "online" | "offline";
  memberIds?: string[];
  trustState?: "trusted" | "unverified" | "changed";
  trustWarning?: string;
}

export interface Message {
  id: string;
  senderId: string;
  recipientId: string;
  conversationId?: string;
  groupId?: string;
  groupName?: string;
  groupMemberIds?: string[];
  groupEventType?: "group_message" | "group_membership";
  groupMembershipCommitment?: string;
  deliveredByUserIds?: string[];
  readByUserIds?: string[];
  content: string; // Decrypted content
  timestamp: number;
  isPqcProtected: boolean; // Indicator for hybrid encryption
  status: "sending" | "sent" | "delivered" | "read" | "error";
}

export interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
}
