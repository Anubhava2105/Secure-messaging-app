import React, { useState } from "react";
import { useAuth } from "../contexts/AuthContext";
import { Atom, Shield, Sparkles, Ban } from "lucide-react";
import "../styles/Auth.css";

const Auth: React.FC = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const { register, login, isLoading, error } = useAuth();
  const [step, setStep] = useState<"welcome" | "generating">("welcome");
  const [mode, setMode] = useState<"register" | "login">("register");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || password.length < 8) return;

    if (mode === "register") {
      setStep("generating");
      await register(username, password);
    } else {
      setStep("generating");
      const success = await login(username, password);
      if (!success) {
        setStep("welcome");
      }
    }
  };

  if (step === "generating") {
    return (
      <div className="auth-container">
        <div className="generation-box">
          <div className="pqc-indicator">
            <div className="pulse-ring"></div>
            <div className="quantum-icon">
              <Atom size={48} />
            </div>
          </div>
          <h2>
            {mode === "register" ? "Securing Your Identity" : "Logging In"}
          </h2>
          <p className="status-text">
            {mode === "register"
              ? "Generating hybrid ECC + ML-KEM key bundles..."
              : "Authenticating with the server..."}
          </p>
          <div className="progress-bar">
            <div className="progress-fill"></div>
          </div>
          <p className="security-note">
            {mode === "register"
              ? "This process is performed entirely locally for maximum security."
              : "Verifying your credentials..."}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="auth-container">
      <div className="welcome-box fadeIn">
        <h1 className="gradient-text">Cipher</h1>
        <p className="subtitle">Post-Quantum Resistant Messaging</p>

        <form onSubmit={handleSubmit} className="auth-form">
          <div className="input-group">
            <label htmlFor="username">
              {mode === "register" ? "Choose your alias" : "Enter your alias"}
            </label>
            <input
              id="username"
              type="text"
              placeholder="e.g. Satoshi"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              disabled={isLoading}
              autoFocus
            />
          </div>

          <div className="input-group">
            <label htmlFor="password">
              {mode === "register"
                ? "Create a password"
                : "Enter your password"}
            </label>
            <input
              id="password"
              type="password"
              placeholder="At least 8 characters"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={isLoading}
              minLength={8}
            />
          </div>

          {error && <p className="error-message">{error}</p>}

          <button
            type="submit"
            className="btn-primary"
            disabled={isLoading || !username.trim() || password.length < 8}
          >
            {isLoading
              ? "Processing..."
              : mode === "register"
                ? "Generate Secure Identity"
                : "Login"}
          </button>

          <button
            type="button"
            className="btn-mode-toggle"
            onClick={() => setMode(mode === "register" ? "login" : "register")}
            disabled={isLoading}
          >
            {mode === "register"
              ? "Already have an account? Login"
              : "New user? Create account"}
          </button>
        </form>

        <div className="security-features">
          <div className="feature">
            <span className="icon">
              <Shield size={18} />
            </span>
            <span>ECC P-384</span>
          </div>
          <div className="feature">
            <span className="icon">
              <Sparkles size={18} />
            </span>
            <span>ML-KEM-768</span>
          </div>
          <div className="feature">
            <span className="icon">
              <Ban size={18} />
            </span>
            <span>Zero Knowledge</span>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Auth;
