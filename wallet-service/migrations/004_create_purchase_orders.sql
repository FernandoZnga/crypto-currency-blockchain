CREATE TABLE IF NOT EXISTS purchase_orders (
    purchase_id UUID PRIMARY KEY,
    owner_user_id UUID NOT NULL,
    wallet_address TEXT NOT NULL,
    amount_usd INTEGER NOT NULL,
    edu_amount INTEGER NOT NULL,
    payment_method_type TEXT NOT NULL,
    payment_payload JSONB NOT NULL,
    status TEXT NOT NULL,
    provider_reference TEXT NOT NULL,
    blockchain_tx_id TEXT,
    created_at TIMESTAMPTZ NOT NULL
);
