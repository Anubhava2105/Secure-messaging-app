/**
 * Authentication Context.
 * Manages user authentication state: login, register, logout.
 */

import React, { createContext, useContext, useState, useEffect } from "react";
import type { AuthState } from "../types";
import { getKeyStore } from "../crypto/storage/keystore";
import { generateExportableECDHKeyPair } from "../crypto/ecc/ecdh";
import {
  generateSigningKeyPair,
  importSigningPublicKey,
  signPrekey,
} from "../crypto/ecc/ecdsa";
import { getMlKem768 } from "../crypto/pqc/mlkem";
import { bytesToBase64 } from "../crypto/utils/encoding";
import {
  registerUser as apiRegisterUser,
  loginUser as apiLoginUser,
  setAuthToken,
  getAuthToken,
  getPrekeyCount,
  uploadPrekeys,
} from "../services/api";
import { createPasswordHash } from "../utils/passwordHash";

const PREKEY_THRESHOLD = 5;
const PREKEY_BATCH_SIZE = 10;
const PREKEY_CHECK_INTERVAL_MS = 5 * 60 * 1000;

interface AuthContextType extends AuthState {
  register: (username: string, password: string) => Promise<void>;
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

function tryGetUserIdFromToken(token: string | null): string | null {
  if (!token) return null;
  try {
    const [, payload] = token.split(".");
    if (!payload) return null;
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(normalized));
    return typeof json?.userId === "string" ? json.userId : null;
  } catch {
    return null;
  }
}

function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(
    bytes.byteOffset,
    bytes.byteOffset + bytes.byteLength
  ) as ArrayBuffer;
}

async function importEcdhPublicFromRaw(rawKey: Uint8Array): Promise<CryptoKey> {
  return await crypto.subtle.importKey(
    "raw",
    toArrayBufferCopy(rawKey),
    { name: "ECDH", namedCurve: "P-384" },
    true,
    []
  );
}

// ===== Helper: Store identity in local keystore =====
async function storeLocalIdentity(
  userId: string,
  username: string,
  params: {
    eccIdentityPublicRaw: Uint8Array;
    eccIdentityPrivateKey: CryptoKey;
    signingPublicRaw: Uint8Array;
    signingPrivateKey: CryptoKey;
    pqcPublic: Uint8Array;
    pqcPrivate: Uint8Array;
  }
): Promise<void> {
  const store = getKeyStore();
  const eccIdentityPublic = (await crypto.subtle.exportKey(
    "jwk",
    await importEcdhPublicFromRaw(params.eccIdentityPublicRaw)
  )) as JsonWebKey;
  const eccIdentityPrivate = (await crypto.subtle.exportKey(
    "jwk",
    params.eccIdentityPrivateKey
  )) as JsonWebKey;
  const signingPublic = (await crypto.subtle.exportKey(
    "jwk",
    await importSigningPublicKey(params.signingPublicRaw)
  )) as JsonWebKey;
  const signingPrivate = (await crypto.subtle.exportKey(
    "jwk",
    params.signingPrivateKey
  )) as JsonWebKey;

  await store.storeIdentity({
    id: userId,
    userId,
    username,
    eccIdentityPublic,
    eccIdentityPrivate,
    pqcIdentityPublic: toArrayBufferCopy(params.pqcPublic),
    pqcIdentityPrivate: toArrayBufferCopy(params.pqcPrivate),
    signingPublic,
    signingPrivate,
    createdAt: Date.now(),
  });
}

// ===== Helper: Generate ML-KEM keypair =====
async function generatePqcKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  const mlkem = await getMlKem768();
  return await mlkem.keypair();
}

// ===== Helper: Replenish one-time prekeys =====
async function replenishPrekeys(userId: string): Promise<void> {
  try {
    const store = getKeyStore();
    const count = await getPrekeyCount();
    if (count >= PREKEY_THRESHOLD) {
      console.log(`[Auth] Prekey count (${count}) is sufficient`);
      return;
    }
    console.log(
      `[Auth] Prekey count (${count}) below threshold, generating...`
    );
    const prekeys: { id: number; publicKey: string }[] = [];
    for (let i = 0; i < PREKEY_BATCH_SIZE; i++) {
      const id = Date.now() + i;
      const kp = await generateExportableECDHKeyPair();

      const privateJwk = (await crypto.subtle.exportKey(
        "jwk",
        kp.privateKey
      )) as JsonWebKey;

      await store.storeSignedPrekey(
        {
          id: `ecc-${id}`,
          type: "ecc",
          prekeyId: id,
          publicKey: toArrayBufferCopy(kp.publicKeyBytes),
          privateKey: privateJwk,
          signature: new ArrayBuffer(0),
          createdAt: Date.now(),
        },
        userId
      );

      prekeys.push({
        id,
        publicKey: bytesToBase64(kp.publicKeyBytes),
      });
    }
    await uploadPrekeys(prekeys);
    console.log(`[Auth] Uploaded ${PREKEY_BATCH_SIZE} new prekeys`);
  } catch (err) {
    console.error("[Auth] Prekey replenishment failed:", err);
  }
}

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({
  children,
}) => {
  const [state, setState] = useState<AuthState>({
    user: null,
    isAuthenticated: false,
    isLoading: true,
    error: null,
  });

  // Check for existing session on mount
  useEffect(() => {
    const checkInitialAuth = async () => {
      try {
        const store = getKeyStore();
        const token = getAuthToken();
        const tokenUserId = tryGetUserIdFromToken(token);
        let identity = tokenUserId
          ? await store.getIdentity(tokenUserId)
          : null;

        // Backward compatibility: migrate legacy single-identity record.
        if (!identity && tokenUserId) {
          const legacyIdentity = await store.getIdentity("local-user");
          if (legacyIdentity?.userId === tokenUserId) {
            await store.storeIdentity({
              ...legacyIdentity,
              id: tokenUserId,
            });
            identity = legacyIdentity;
          }
        }

        if (identity && token) {
          setState({
            user: { id: identity.userId, username: identity.username || "Me" },
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } else {
          // If token is missing/cleared, force logged-out state.
          if (tokenUserId && !token) {
            await store.clearAll();
          }
          setState((s) => ({ ...s, isLoading: false }));
        }
      } catch (err) {
        console.error("Initial auth check failed:", err);
        setState((s) => ({ ...s, isLoading: false }));
      }
    };

    checkInitialAuth();
  }, []);

  // ===== Register =====
  const register = async (username: string, password: string) => {
    setState((s) => ({ ...s, isLoading: true, error: null }));

    try {
      const normalizedUsername = username.trim();
      if (!normalizedUsername) {
        throw new Error("Username is required");
      }

      // Generate identity keys
      console.log("[Auth] Generating identity keys...");
      const eccIdentity = await generateExportableECDHKeyPair();
      const signingKey = await generateSigningKeyPair();
      const pqcIdentity = await generatePqcKeypair();

      // Generate signed prekeys
      const prekeyId = 1;
      const timestamp = Date.now();
      const prekeyEcc = await generateExportableECDHKeyPair();
      const prekeySignature = await signPrekey(
        signingKey.privateKey,
        prekeyEcc.publicKeyBytes,
        prekeyId,
        timestamp
      );
      const prekeyPqc = await generatePqcKeypair();
      const pqcPrekeySignature = await signPrekey(
        signingKey.privateKey,
        prekeyPqc.publicKey,
        prekeyId,
        timestamp
      );

      // Create password hash from actual user-supplied password
      const passwordHash = await createPasswordHash(normalizedUsername, password);

      // Register with server
      console.log("[Auth] Registering with server...");
      const serverResponse = await apiRegisterUser({
        username: normalizedUsername,
        passwordHash,
        identityKeyEccPub: bytesToBase64(eccIdentity.publicKeyBytes),
        identityKeyPqcPub: bytesToBase64(pqcIdentity.publicKey),
        signingKeyPub: bytesToBase64(signingKey.publicKeyBytes),
        signedPrekeyEcc: {
          id: prekeyId,
          publicKey: bytesToBase64(prekeyEcc.publicKeyBytes),
          signature: bytesToBase64(prekeySignature),
          createdAt: timestamp,
        },
        signedPrekeyPqc: {
          id: prekeyId,
          publicKey: bytesToBase64(prekeyPqc.publicKey),
          signature: bytesToBase64(pqcPrekeySignature),
          createdAt: timestamp,
        },
      });

      if (!serverResponse) {
        throw new Error("Registration failed - server returned null");
      }

      // Store identity locally
      await storeLocalIdentity(serverResponse.userId, normalizedUsername, {
        eccIdentityPublicRaw: eccIdentity.publicKeyBytes,
        eccIdentityPrivateKey: eccIdentity.privateKey,
        signingPublicRaw: signingKey.publicKeyBytes,
        signingPrivateKey: signingKey.privateKey,
        pqcPublic: pqcIdentity.publicKey,
        pqcPrivate: pqcIdentity.privateKey,
      });

      // Persist signed prekeys required by responder-side handshake.
      const store = getKeyStore();
      const prekeyEccPrivateJwk = (await crypto.subtle.exportKey(
        "jwk",
        prekeyEcc.privateKey
      )) as JsonWebKey;
      await store.storeSignedPrekey(
        {
          id: `ecc-${prekeyId}`,
          type: "ecc",
          prekeyId,
          publicKey: toArrayBufferCopy(prekeyEcc.publicKeyBytes),
          privateKey: prekeyEccPrivateJwk,
          signature: toArrayBufferCopy(prekeySignature),
          createdAt: timestamp,
        },
        serverResponse.userId
      );
      await store.storeSignedPrekey(
        {
          id: `pqc-${prekeyId}`,
          type: "pqc",
          prekeyId,
          publicKey: toArrayBufferCopy(prekeyPqc.publicKey),
          privateKey: toArrayBufferCopy(prekeyPqc.privateKey),
          signature: toArrayBufferCopy(prekeySignature),
          createdAt: timestamp,
        },
        serverResponse.userId
      );

      console.log("[Auth] Registration complete:", serverResponse.userId);
      setState({
        user: { id: serverResponse.userId, username: normalizedUsername },
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });
    } catch (err) {
      console.error("[Auth] Registration error:", err);
      setState((s) => ({
        ...s,
        isLoading: false,
        error: (err as Error).message,
      }));
    }
  };

  // ===== Login =====
  const login = async (username: string, password: string): Promise<boolean> => {
    setState((s) => ({ ...s, isLoading: true, error: null }));

    try {
      const normalizedUsername = username.trim();
      if (!normalizedUsername) {
        setState((s) => ({
          ...s,
          isLoading: false,
          error: "Username is required",
        }));
        return false;
      }

      const passwordHash = await createPasswordHash(normalizedUsername, password);
      const response = await apiLoginUser(normalizedUsername, passwordHash);

      if (!response) {
        setState((s) => ({
          ...s,
          isLoading: false,
          error: "Invalid credentials",
        }));
        return false;
      }

      // Require existing local key material for secure operation.
      const store = getKeyStore();
      let localIdentity = await store.getIdentity(response.userId);

      // Backward compatibility: migrate legacy single-identity record.
      if (!localIdentity) {
        const legacyIdentity = await store.getIdentity("local-user");
        if (legacyIdentity?.userId === response.userId) {
          await store.storeIdentity({
            ...legacyIdentity,
            id: response.userId,
          });
          localIdentity = legacyIdentity;
        }
      }

      if (!localIdentity || localIdentity.userId !== response.userId) {
        setAuthToken(null);
        setState((s) => ({
          ...s,
          isLoading: false,
          error:
            "No matching local key material found for this account on this browser profile/origin. This commonly happens if local storage was cleared or an older build removed keys on logout. Use the same profile+origin where this alias was created, or create a new alias.",
        }));
        return false;
      }

      setState({
        user: { id: response.userId, username: response.username },
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      console.log("[Auth] Login successful:", response.username);

      // Replenish prekeys if needed
      replenishPrekeys(response.userId).catch(console.error);

      return true;
    } catch (err) {
      console.error("[Auth] Login error:", err);
      setState((s) => ({
        ...s,
        isLoading: false,
        error: (err as Error).message,
      }));
      return false;
    }
  };

  // ===== Logout =====
  const logout = async () => {
    setAuthToken(null);
    const store = getKeyStore();
    await store.clearRuntimeData();
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  };

  // Periodic prekey health check while authenticated.
  useEffect(() => {
    if (!state.isAuthenticated || !state.user?.id) return;

    const id = setInterval(() => {
      replenishPrekeys(state.user!.id).catch(console.error);
    }, PREKEY_CHECK_INTERVAL_MS);

    return () => clearInterval(id);
  }, [state.isAuthenticated, state.user, state.user?.id]);

  return (
    <AuthContext.Provider value={{ ...state, register, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

// eslint-disable-next-line react-refresh/only-export-components
export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
