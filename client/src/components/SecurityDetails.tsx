import React from "react";
import { ShieldCheck } from "lucide-react";
import "../styles/SecurityDetails.css";

interface SecurityDetailsProps {
  isOpen: boolean;
  onClose: () => void;
  sessionInfo: {
    peerName: string;
    eccCurve: string;
    pqcAlgorithm: string;
    keyExchange: string;
    kdf: string;
    cipher: string;
  };
}

const SecurityDetails: React.FC<SecurityDetailsProps> = ({
  isOpen,
  onClose,
  sessionInfo,
}) => {
  if (!isOpen) return null;

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content glass" onClick={(e) => e.stopPropagation()}>
        <header className="modal-header">
          <div className="pqc-banner">Quantum Resistant Session</div>
          <button className="close-btn" onClick={onClose}>
            &times;
          </button>
        </header>

        <div className="modal-body">
          <div className="security-visual">
            <div className="shield-icon">
              <ShieldCheck size={48} />
            </div>
            <div className="status-badge">E2EE + PQC Active</div>
          </div>

          <p className="description">
            Your conversation with <strong>{sessionInfo.peerName}</strong> is
            secured using a hybrid cryptographic protocol. Even a future
            cryptographically relevant quantum computer (CRQC) cannot decrypt
            your messages.
          </p>

          <div className="spec-grid">
            <div className="spec-item">
              <label>Classical Key Exchange</label>
              <span>{sessionInfo.eccCurve}</span>
            </div>
            <div className="spec-item highlighted">
              <label>Post-Quantum KEM</label>
              <span>{sessionInfo.pqcAlgorithm}</span>
            </div>
            <div className="spec-item">
              <label>Protocol</label>
              <span>{sessionInfo.keyExchange}</span>
            </div>
            <div className="spec-item">
              <label>Key Derivation</label>
              <span>{sessionInfo.kdf}</span>
            </div>
            <div className="spec-item">
              <label>Encryption</label>
              <span>{sessionInfo.cipher}</span>
            </div>
          </div>
        </div>

        <footer className="modal-footer">
          <button className="btn-primary" onClick={onClose}>
            Understood
          </button>
        </footer>
      </div>
    </div>
  );
};

export default SecurityDetails;
