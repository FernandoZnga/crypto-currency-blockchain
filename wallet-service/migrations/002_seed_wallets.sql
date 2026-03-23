INSERT INTO wallets (
    wallet_id, owner_user_id, owner, address, type, seed_balance
) VALUES
(
    '95e5c677-c195-4c6e-8ee8-bfe679f2956f',
    '6f2a68f2-0a52-4d41-8b2b-4f26dd97d81f',
    'Alice',
    'alice-edu-wallet',
    'hot',
    12000
),
(
    '5a18fc4c-f766-4ef6-8c27-502d31bbaf42',
    '4c4c3fe6-aabe-4b0c-a4cb-6d4b85af0d36',
    'Bob',
    'bob-edu-wallet',
    'warm',
    3500
),
(
    'af348d2a-f566-4698-93a8-cd3561904ef3',
    'a5001f77-bbb7-4a33-bb65-ac4f8d6559c6',
    'Treasury',
    'treasury-edu-wallet',
    'cold',
    50000
)
ON CONFLICT (wallet_id) DO NOTHING;
