# Timestamping Service

**Foundations of Cybersecurity Project (A.Y. 2025/2026), University of Pisa**

**Evaluation: Very Good**

## Overview

A Timestamping Service (TSS) is a trusted third-party service that provides a legally valid, cryptographically signed record proving that specific electronic data (documents, code, logs) existed at a precise date and time.

Rather than signing the entire data, the server signs a cryptographic hash of the data, provided by the requesting user, along with a timestamp. This inextricable binding creates a solid time proof for the document's hash.

The system follows a client-server architecture: a multi-threaded **server** authenticates users and signs document hashes, while multiple **clients** connect to perform operations after authentication.

## Supported Operations

Once the secure channel is established and the user is authenticated via their credentials (username and password), the client can perform the following operations:

| Operation | Description |
|---|---|
| **Balance** | Show the number of available and consumed timestamps. |
| **Sign** | Ask the server to sign a document's hash. The client calculates the SHA-256 hash locally and sends only the digest to the server. |
| **Verify** | Verify previously obtained signatures locally, without interacting with the server and without an account required. The client scans the local `Signatures.txt` file to validate the cryptographic signature against the server's long-term public signature key. |
| **Exit** | Close the connection with the server and shutdown. |

## Secure Channel

All interactions are performed through a secure channel established during an initial handshake, providing **Perfect Forward Secrecy** (via ECDHE), **confidentiality and integrity** (AES-256-GCM), **server authentication** (digital signatures over ephemeral keys), and **anti-replay protection** (fresh nonces at handshake, sequence numbers as AAD during the session).

## Prerequisites

- A compiler compatible with C++20 (e.g., `g++`)
- The OpenSSL library installed on your system
- The `nlohmann-json` library for JSON handling, which can be installed via:
  ```bash
  sudo apt install nlohmann-json3-dev
  ```

## Compilation and Execution

The project includes a `makefile` to automate the build process.

**Compile:**
```bash
make
```

**Start the server:**
```bash
./sv [port]
```
If no port is specified, the server defaults to port `8080`.

**Start the client:**
```bash
./cl [port]
```

## Authors

- Sebastiano Pala
- Eleonora Sgorbini