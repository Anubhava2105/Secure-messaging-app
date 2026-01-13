# Secure Messaging App Architecture

## Overview
This document outlines the high-level architecture of the Secure Messaging App, designed to provide end-to-end encrypted communication between users.

## System Components

### 1. Client Application
- **Mobile/Web Interface**: Built using React Native / React.
- **Local Storage**: Encrypted local database (Realm/SQLite) for storing message history and keys.
- **Cryptography Module**: Handles key generation (RSA/ECC), encryption (AES-256), and signing.

### 2. Backend Server
- **API Gateway**: REST/GraphQL endpoints for user registration, authentication, and message routing.
- **WebSocket Server**: Handles real-time message delivery and presence status.
- **Database**: Stores user profiles and ephemeral message queues (messages are deleted after delivery).
- **Push Notification Service**: Integrates with FCM/APNs for offline notifications.

## Security Architecture

### End-to-End Encryption (E2EE)
- Messages are encrypted on the sender's device and decrypted only on the recipient's device.
- The server has no access to private keys or plaintext messages.

### Authentication
- JWT-based authentication for API access.
- Multi-factor authentication support.

### Key Management
- Public keys are stored on the server for user discovery.
- Private keys never leave the user's device.

## Data Flow
1. **User Registration**: Client generates key pair; Public key sent to server.
2. **Sending a Message**:
   - Client fetches recipient's public key.
   - Encrypts message with a symmetric session key.
   - Encrypts session key with recipient's public key.
   - Sends encrypted payload to server.
3. **Receiving a Message**:
   - Server pushes encrypted payload to recipient via WebSocket.
   - Recipient decrypts session key with private key.
   - Decrypts message content.

## Future Considerations
- Group chat E2EE using Sender Keys.
- Voice/Video call signaling.
