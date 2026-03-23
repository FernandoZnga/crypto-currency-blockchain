CREATE TABLE IF NOT EXISTS wallets (
    wallet_id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL,
    owner TEXT NOT NULL,
    address TEXT NOT NULL UNIQUE,
    type TEXT NOT NULL,
    seed_balance INTEGER NOT NULL
);
