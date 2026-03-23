# Service Contracts

This file defines the first-pass contracts that the UI and services should build against.

## Blockchain Node

`GET /network`

- Returns node identity, role, peers, chain height, latest block, mempool size, and recent activity.

`GET /chain`

- Returns the full in-memory chain for synchronization.

`GET /mempool`

- Returns current unconfirmed transactions.

`POST /transactions`

- Creates a new transaction at the receiving node.
- Payload:

```json
{
  "sender": "wallet-a",
  "recipient": "wallet-b",
  "amount": 25,
  "nonce": "client-generated-id"
}
```

`POST /transactions/receive`

- Internal peer-to-peer endpoint used to propagate transactions.

`POST /blocks/receive`

- Internal peer-to-peer endpoint used to propagate accepted blocks.

## API Gateway

`GET /health`

- Service liveness endpoint.

`GET /topology`

- Returns core upstream URLs.

`GET /network/overview`

- Aggregates live state from all configured blockchain nodes for the frontend.

`POST /register`

- Creates a user account with a linked wallet address.
- `user_id` values are UUIDs.

`POST /login`

- Issues a bearer token for subsequent requests.

`GET /me`

- Returns the authenticated user and recent KYC submissions.

`POST /kyc-submissions`

- Records a KYC submission for the authenticated user and moves status to `pending_review`.
- `submission_id` values are UUIDs.

`GET /wallets/by-owner?owner_user_id=<id>`

- Returns wallets owned by a user plus network contacts for transfer recipients.
- `owner_user_id` and `wallet_id` values are UUIDs.

## Audit Log Shape

See [`shared/schemas/audit-event.schema.json`](/Users/fzuniga/Projects/master/crypto-currency-blockchain/shared/schemas/audit-event.schema.json).
