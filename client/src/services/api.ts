/**
 * API Service for communicating with the relay server.
 *
 * Handles HTTP requests for user discovery and prekey fetching.
 * SECURITY: Only public data is transferred. No private keys.
 */

import { API_BASE_URL } from "../constants";

/** In-memory JWT token storage */
const AUTH_TOKEN_STORAGE_KEY = "securemsg.authToken";

function readStoredToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    const sessionToken = window.sessionStorage.getItem(AUTH_TOKEN_STORAGE_KEY);
    if (sessionToken) return sessionToken;

    // Backward compatibility: migrate from old localStorage token.
    const legacyToken = window.localStorage.getItem(AUTH_TOKEN_STORAGE_KEY);
    if (legacyToken) {
      window.sessionStorage.setItem(AUTH_TOKEN_STORAGE_KEY, legacyToken);
      window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
      return legacyToken;
    }

    return null;
  } catch {
    return null;
  }
}

let authToken: string | null = readStoredToken();

/** Get the current auth token (used by WebSocket) */
export function getAuthToken(): string | null {
  return authToken;
}

/** Set the auth token (called after login/register) */
export function setAuthToken(token: string | null): void {
  authToken = token;

  if (typeof window === "undefined") return;
  try {
    if (token) {
      window.sessionStorage.setItem(AUTH_TOKEN_STORAGE_KEY, token);
      // Keep localStorage clear to avoid cross-tab token collisions.
      window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    } else {
      window.sessionStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
      window.localStorage.removeItem(AUTH_TOKEN_STORAGE_KEY);
    }
  } catch {
    // Ignore storage errors (private mode, quota, etc.)
  }
}

/** Build headers with optional auth */
function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (authToken) {
    headers["Authorization"] = `Bearer ${authToken}`;
  }
  return headers;
}

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
  username: string
): Promise<UserInfo | null> {
  try {
    const response = await fetch(
      `${API_BASE_URL}/users/${encodeURIComponent(username)}`
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
      `${API_BASE_URL}/users/id/${encodeURIComponent(userId)}`
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
  userId: string
): Promise<PreKeyBundleDTO | null> {
  try {
    const response = await fetch(
      `${API_BASE_URL}/users/${encodeURIComponent(userId)}/prekeys`
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
 * Stores the JWT token on success.
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
}): Promise<{ userId: string; username: string; token: string } | null> {
  try {
    const response = await fetch(`${API_BASE_URL}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    if (!response.ok) {
      const errorBody = await response.json().catch(() => ({}));
      throw new Error(
        errorBody.error || `Registration failed: ${response.statusText}`
      );
    }
    const result = await response.json();
    // Store token
    setAuthToken(result.token);
    return result;
  } catch (error) {
    console.error("Error registering user:", error);
    throw error;
  }
}

/**
 * Login an existing user.
 * Stores the JWT token on success.
 */
export async function loginUser(
  username: string,
  passwordHash: string
): Promise<{ userId: string; username: string; token: string } | null> {
  const response = await fetch(`${API_BASE_URL}/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, passwordHash }),
  });
  if (!response.ok) {
    if (response.status === 401) return null;
    const errorBody = await response.json().catch(() => ({}));
    throw new Error(errorBody.error || `Login failed: ${response.statusText}`);
  }
  const result = await response.json();
  // Store token
  setAuthToken(result.token);
  return result;
}

/**
 * Get current one-time prekey count.
 * Requires authentication.
 */
export async function getPrekeyCount(): Promise<number> {
  try {
    const response = await fetch(`${API_BASE_URL}/prekeys/count`, {
      headers: authHeaders(),
    });
    if (!response.ok) return 0;
    const data = await response.json();
    return data.count ?? 0;
  } catch {
    return 0;
  }
}

/**
 * Upload additional one-time prekeys.
 * Requires authentication.
 */
export async function uploadPrekeys(
  prekeys: OneTimePreKey[]
): Promise<boolean> {
  try {
    const response = await fetch(`${API_BASE_URL}/prekeys`, {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ oneTimePrekeys: prekeys }),
    });
    return response.ok;
  } catch {
    return false;
  }
}
