/**
 * API Service for communicating with the relay server.
 *
 * Handles HTTP requests for user discovery and prekey fetching.
 * SECURITY: Only public data is transferred. No private keys.
 */

const API_BASE_URL = "http://localhost:3000/api/v1";

export interface UserInfo {
  userId: string;
  username: string;
}

export interface SignedPreKey {
  id: number;
  publicKey: string;
  signature: string;
  createdAt: number;
}

export interface OneTimePreKey {
  id: number;
  publicKey: string;
}

export interface PreKeyBundleDTO {
  userId: string;
  identityKeyEccPub: string;
  identityKeyPqcPub: string;
  signingKeyPub: string;
  signedPrekeyEcc: SignedPreKey;
  signedPrekeyPqc: SignedPreKey;
  oneTimePrekeyEcc?: OneTimePreKey;
}

/**
 * Find a user by their username.
 * Used for contact discovery.
 */
export async function findUserByUsername(
  username: string,
): Promise<UserInfo | null> {
  try {
    const response = await fetch(
      `${API_BASE_URL}/users/${encodeURIComponent(username)}`,
    );
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`Failed to find user: ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error finding user:", error);
    return null;
  }
}

/**
 * Find a user by their user ID.
 * Used to look up usernames when receiving messages from unknown senders.
 */
export async function findUserById(userId: string): Promise<UserInfo | null> {
  try {
    const response = await fetch(
      `${API_BASE_URL}/users/id/${encodeURIComponent(userId)}`,
    );
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`Failed to find user: ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error finding user by ID:", error);
    return null;
  }
}

/**
 * Fetch a user's prekey bundle for initiating a key exchange.
 * SECURITY: One-time prekeys are consumed atomically by the server.
 */
export async function getPreKeyBundle(
  userId: string,
): Promise<PreKeyBundleDTO | null> {
  try {
    const response = await fetch(
      `${API_BASE_URL}/users/${encodeURIComponent(userId)}/prekeys`,
    );
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`Failed to fetch prekeys: ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error fetching prekey bundle:", error);
    return null;
  }
}

/**
 * Register a new user with their public keys.
 */
export async function registerUser(data: {
  username: string;
  passwordHash: string;
  identityKeyEccPub: string;
  identityKeyPqcPub: string;
  signingKeyPub: string;
  signedPrekeyEcc: SignedPreKey;
  signedPrekeyPqc: SignedPreKey;
  oneTimePrekeyEcc?: OneTimePreKey[];
}): Promise<{ userId: string; username: string } | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(
        errorBody.error || `Registration failed: ${response.statusText}`,
      );
    }
    return await response.json();
  } catch (error) {
    console.error("Error registering user:", error);
    throw error;
  }
}

/**
 * Login an existing user.
 */
export async function loginUser(
  username: string,
  passwordHash: string,
): Promise<{ userId: string; username: string; token: string } | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, passwordHash }),
    });
    if (!response.ok) {
      if (response.status === 401) return null;
      throw new Error(`Login failed: ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error("Error logging in:", error);
    return null;
  }
}
