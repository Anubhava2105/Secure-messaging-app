export interface User {
  id: string;
  username: string;
  lastSeen?: number;
}

export interface Contact extends User {
  publicKeyEcc: Uint8Array;
  publicKeyPqc: Uint8Array;
  status: "online" | "offline";
}

export interface Message {
  id: string;
  senderId: string;
  recipientId: string;
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
