/**
 * Main Application Component.
 * Composes the app from smaller, focused components.
 */

import { useState } from "react";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { MessengerProvider, useMessenger } from "./contexts/MessengerContext";
import Auth from "./components/Auth";
import Sidebar from "./components/Sidebar";
import ChatArea from "./components/ChatArea";
import EmptyChatState from "./components/EmptyChatState";
import SecurityDetails from "./components/SecurityDetails";
import AddContactModal from "./components/AddContactModal";
import "./styles/App.css";

// ===== Main App Content =====
const AppContent = () => {
  const { isAuthenticated, isLoading, user, logout } = useAuth();
  const {
    contacts,
    activeContact,
    setActiveContact,
    messages,
    sendMessage,
    addContact,
    connectionStatus,
  } = useMessenger();

  const [isSecurityModalOpen, setSecurityModalOpen] = useState(false);
  const [isAddContactModalOpen, setAddContactModalOpen] = useState(false);

  if (isLoading) {
    return (
      <div className="loading-screen">
        <div className="loader"></div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Auth />;
  }

  return (
    <>
      <div className="app-main">
        <Sidebar
          username={user?.username}
          connectionStatus={connectionStatus}
          contacts={contacts}
          activeContact={activeContact}
          onSelectContact={setActiveContact}
          onAddContact={() => setAddContactModalOpen(true)}
          onLogout={logout}
        />

        <main className="chat-area">
          {activeContact ? (
            <ChatArea
              activeContact={activeContact}
              messages={messages}
              currentUserId={user?.id}
              onSendMessage={sendMessage}
              onOpenSecurityDetails={() => setSecurityModalOpen(true)}
            />
          ) : (
            <EmptyChatState onAddContact={() => setAddContactModalOpen(true)} />
          )}
        </main>
      </div>

      <SecurityDetails
        isOpen={isSecurityModalOpen}
        onClose={() => setSecurityModalOpen(false)}
        sessionInfo={{
          peerName: activeContact?.username || "Peer",
          eccCurve: "NIST P-384",
          pqcAlgorithm: "ML-KEM-768 (Kyber)",
          keyExchange: "Hybrid X3DH",
          kdf: "HKDF-SHA-384",
          cipher: "AES-GCM-256",
        }}
      />

      <AddContactModal
        isOpen={isAddContactModalOpen}
        onClose={() => setAddContactModalOpen(false)}
        onAdd={addContact}
      />
    </>
  );
};

function App() {
  return (
    <AuthProvider>
      <MessengerProvider>
        <AppContent />
      </MessengerProvider>
    </AuthProvider>
  );
}

export default App;
