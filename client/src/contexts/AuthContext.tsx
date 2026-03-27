/**
 * Authentication Context.
 * Manages user authentication state: login, register, logout.
 */

import React, { createContext, useContext, useState, useEffect } from "react";
import type { AuthState } from "../types";
import { getKeyStore } from "../crypto/storage/keystore";
import {
  generateECDHKeyPair,
  generateExportableECDHKeyPair,
} from "../crypto/ecc/ecdh";
import { generateSigningKeyPair, signPrekey } from "../crypto/ecc/ecdsa";
import { getMlKem768 } from "../crypto/pqc/mlkem";
import { bytesToBase64 } from "../crypto/utils/encoding";
import {
  registerUser as apiRegisterUser,
  loginUser as apiLoginUser,
} from "../services/api";
import { createPasswordHash } from "../utils/passwordHash";

interface AuthContextType extends AuthState {
  register: (username: string) => Promise<void>;
  login: (username: string) => Promise<boolean>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// ===== Helper: Store identity in local keystore =====
async function storeLocalIdentity(
  userId: string,
  username: string,
  eccJwk: JsonWebKey,
  pqcPublic: ArrayBuffer = new ArrayBuffer(0),
  pqcPrivate: ArrayBuffer = new ArrayBuffer(0),
): Promise<void> {
  const store = getKeyStore();
  await store.storeIdentity({
    id: "local-user",
    userId,
    username,
    eccIdentityPublic: eccJwk,
    pqcIdentityPublic: pqcPublic,
    pqcIdentityPrivate: pqcPrivate,
    signingPublic: eccJwk,
    createdAt: Date.now(),
  });
}

// ===== Helper: Generate ML-KEM keypair with fallback =====
async function generatePqcKeypair(): Promise<{
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}> {
  try {
    const mlkem = await getMlKem768();
    return await mlkem.keypair();
  } catch {
    console.warn("[Auth] PQC Key generation fallback used");
    return {
      publicKey: new Uint8Array(1184),
      privateKey: new Uint8Array(2400),
    };
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
        const identity = await store.getIdentity("local-user");

        if (identity) {
          setState({
            user: { id: identity.userId, username: identity.username || "Me" },
            isAuthenticated: true,
            isLoading: false,
            error: null,
          });
        } else {
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
  const register = async (username: string) => {
    setState((s) => ({ ...s, isLoading: true, error: null }));

    try {
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
        timestamp,
      );
      const prekeyPqc = await generatePqcKeypair();

      // Create password hash
      const passwordHash = await createPasswordHash(username);

      // Register with server
      console.log("[Auth] Registering with server...");
      const serverResponse = await apiRegisterUser({
        username,
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
          signature: bytesToBase64(prekeySignature),
          createdAt: timestamp,
        },
      });

      if (!serverResponse) {
        throw new Error("Registration failed - server returned null");
      }

      // Store identity locally
      const simpleEccPair = await generateECDHKeyPair();
      const eccJwk = await crypto.subtle.exportKey(
        "jwk",
        simpleEccPair.publicKey,
      );
      await storeLocalIdentity(
        serverResponse.userId,
        username,
        eccJwk,
        pqcIdentity.publicKey.buffer as ArrayBuffer,
        pqcIdentity.privateKey.buffer as ArrayBuffer,
      );

      console.log("[Auth] Registration complete:", serverResponse.userId);
      setState({
        user: { id: serverResponse.userId, username },
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
  const login = async (username: string): Promise<boolean> => {
    setState((s) => ({ ...s, isLoading: true, error: null }));

    try {
      const passwordHash = await createPasswordHash(username);
      const response = await apiLoginUser(username, passwordHash);

      if (!response) {
        setState((s) => ({
          ...s,
          isLoading: false,
          error: "Invalid credentials",
        }));
        return false;
      }

      // Store identity locally
      const simpleEccPair = await generateECDHKeyPair();
      const eccJwk = await crypto.subtle.exportKey(
        "jwk",
        simpleEccPair.publicKey,
      );
      await storeLocalIdentity(response.userId, response.username, eccJwk);

      setState({
        user: { id: response.userId, username: response.username },
        isAuthenticated: true,
        isLoading: false,
        error: null,
      });

      console.log("[Auth] Login successful:", response.username);
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
    const store = getKeyStore();
    await store.clearAll();
    setState({
      user: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
    });
  };

  return (
    <AuthContext.Provider value={{ ...state, register, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};
