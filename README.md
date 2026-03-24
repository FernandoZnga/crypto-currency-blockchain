<div align="center">

# Educational Crypto Network

**A multi-node blockchain platform built for learning — wallets, KYC, transactions, and peer propagation in one stack.**

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Prometheus](https://img.shields.io/badge/Prometheus-Monitoring-E6522C?logo=prometheus&logoColor=white)
![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red)
![Status](https://img.shields.io/badge/Status-Educational-blueviolet)

</div>

---

## Overview

This is a **production-like educational cryptocurrency network** that runs entirely in Docker Compose. It is designed so you can observe how real blockchain concepts work — peer discovery, transaction signing with ECDSA, block propagation, KYC compliance anchoring, and multi-node consensus — without touching real money or mainnet infrastructure.

> **No real funds are involved.** Every token, wallet, and transaction exists purely for learning.

---

## Architecture

```
┌─────────────┐
│   Frontend   │  :3000  (Nginx)
└──────┬───────┘
       │  edge network
┌──────▼───────┐
│  API Gateway  │  :8000
└──┬───┬───┬───┘
   │   │   │  services network
┌──▼┐ ┌▼──┐ ┌▼────────────┐
│Auth│ │W. │ │ Blockchain   │
│Svc │ │Svc│ │ Nodes (×3)   │
│8001│ │8002│ │8101-8103    │
└─┬──┘ └┬──┘ └─────────────┘
  │     │     data networks
┌─▼──┐ ┌▼───┐
│ PG │ │ PG  │  PostgreSQL 16
│Auth│ │Wall.│
└────┘ └─────┘

+ Audit Service  :8010
+ Prometheus     :9090
```

Docker networks are **tiered** for isolation:
- **edge** — frontend ↔ API gateway
- **services** — gateway ↔ microservices ↔ blockchain nodes
- **auth-data / wallet-data** — each database is isolated to its own service

---

## Features

- **Multi-node blockchain** — 3 nodes with peer-to-peer transaction and block propagation, automatic sync, and bootstrap mining
- **ECDSA transaction signing** — wallets generate secp256k1 key pairs; every payment is cryptographically signed and verified on-chain
- **KYC compliance flow** — submit identity documents, anchor the submission hash on-chain, and go through admin review (approve / deny / resubmit)
- **User authentication** — registration, login with session tokens, PBKDF2 password hashing, and role-based access (user / admin)
- **Wallet management** — create wallets, view balances computed from chain state, and send signed transactions
- **Admin dashboard** — manage users, review KYC submissions, suspend/block accounts, and view platform activity
- **Audit trail** — every significant action emits a structured ISO-aligned audit event stored by the audit service
- **Prometheus metrics** — each service exposes `/metrics` for counters and gauges, scraped by a bundled Prometheus instance
- **Responsive frontend** — landing page, user dashboard, KYC flow, wallet transfers, admin panel, and network explorer all in vanilla HTML/CSS/JS

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.12 (stdlib `http.server`) |
| Cryptography | `cryptography` (ECDSA / secp256k1) |
| Database | PostgreSQL 16 (via `psycopg`) |
| Frontend | Vanilla HTML + CSS + JavaScript |
| Containers | Docker Compose |
| Monitoring | Prometheus |
| Web Server | Nginx (frontend static files) |

---

## Getting Started

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- Git

### 1. Clone the repository

```bash
git clone https://github.com/FernandoZnga/crypto-currency-blockchain.git
cd crypto-currency-blockchain
```

### 2. Configure environment variables

```bash
cp .env.example .env
# Edit .env and replace placeholder passwords
```

### 3. Start the stack

```bash
docker compose up --build
```

### 4. Open the app

| Service | URL |
|---|---|
| Frontend | [http://localhost:3000](http://localhost:3000) |
| API Gateway | [http://localhost:8000/health](http://localhost:8000/health) |
| Blockchain Node 1 | [http://localhost:8101/network](http://localhost:8101/network) |
| Blockchain Node 2 | [http://localhost:8102/network](http://localhost:8102/network) |
| Blockchain Node 3 | [http://localhost:8103/network](http://localhost:8103/network) |
| Audit Service | [http://localhost:8010/summary](http://localhost:8010/summary) |
| Prometheus | [http://localhost:9090](http://localhost:9090) |

---

## Project Structure

```
├── frontend/             # Responsive web UI (Nginx)
├── api-gateway/          # Edge service — routes requests to internal services
├── auth-service/         # Registration, login, sessions, KYC workflow
├── wallet-service/       # Wallet creation, ECDSA key pairs, transaction signing
├── blockchain-node/      # Blockchain node with mining, validation, and P2P sync
├── audit-service/        # Structured audit event collector
├── shared/               # Service contracts and JSON schemas
├── infra/                # Prometheus configuration
├── data/                 # Persistent volumes (git-ignored)
├── docs/                 # Project documentation (PDF / DOCX guides)
├── docker-compose.yml    # Full stack orchestration
└── .env.example          # Environment variable template
```

---

## API Reference

### API Gateway (port 8000)

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/register` | Create a user account with a linked wallet |
| `POST` | `/login` | Authenticate and receive a session token |
| `GET` | `/me` | Get the current authenticated user |
| `POST` | `/kyc-submissions` | Submit a KYC document for review |
| `GET` | `/network/overview` | Aggregated state from all blockchain nodes |
| `GET` | `/wallets/by-owner` | Wallets for a specific user |
| `POST` | `/transactions/send` | Sign and broadcast a transaction |
| `GET` | `/audit/events` | Query audit trail |
| `GET` | `/topology` | Service topology map |

### Blockchain Node (ports 8101–8103)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/network` | Node identity, peers, chain height, mempool |
| `GET` | `/chain` | Full chain for synchronization |
| `GET` | `/mempool` | Pending unconfirmed transactions |
| `POST` | `/transactions` | Submit a signed transaction |
| `POST` | `/transactions/kyc-anchor` | Anchor a KYC hash on-chain |
| `GET` | `/metrics` | Prometheus metrics |

---

## Why Multiple Nodes?

A single-node setup cannot demonstrate the core concepts this project teaches:

- **Peer discovery** — nodes connect via explicit peer lists
- **Transaction propagation** — transactions broadcast across the network
- **Block propagation** — mined blocks are distributed to all validators
- **Chain synchronization** — lagging nodes catch up automatically
- **State divergence** — observe differences between local and network state

The topology includes a **bootstrap node** (node-1) that mines blocks, and two **validator nodes** (node-2, node-3) that validate and accept propagated blocks.

---

## Roadmap

- [x] Multi-node blockchain topology with Docker Compose
- [x] Tiered network isolation (edge / services / data)
- [x] Auth service with registration, login, and session management
- [x] Wallet service with ECDSA key generation and transaction signing
- [x] KYC submission + on-chain anchoring
- [x] Admin dashboard with user management and KYC review
- [x] Audit service with structured event logging
- [x] Prometheus metrics for all services
- [x] Responsive frontend with landing page and authenticated dashboard
- [ ] Integration test suite with seeded demo data
- [ ] WebSocket live updates for chain state
- [ ] Block explorer with transaction detail view

---

## License

This project is for **educational purposes only**. All Rights Reserved © 2026 Fernando Zuniga. See [LICENSE](LICENSE) for details.

---

<div align="center">

Built for learning. Not for production. Not financial advice.

</div>
