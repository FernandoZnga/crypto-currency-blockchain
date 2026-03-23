INSERT INTO users (
    user_id, name, email, password_hash, salt, wallet_address, kyc_status, created_at
) VALUES
(
    '6f2a68f2-0a52-4d41-8b2b-4f26dd97d81f',
    'Alice',
    'alice@example.com',
    'f64c17828b1a87129f05cf5952f4af1f376f2b85a33a62ebbc9fd40d02e9cfcd',
    'salt-6f2a68f2-0a52-4d41-8b2b-4f26dd97d81f',
    'alice-edu-wallet',
    'verified',
    NOW()
),
(
    '4c4c3fe6-aabe-4b0c-a4cb-6d4b85af0d36',
    'Bob',
    'bob@example.com',
    'ab9174656d9c6bdcd381e61c2465687a8044e1bc79521a2641d9f4d6b284b251',
    'salt-4c4c3fe6-aabe-4b0c-a4cb-6d4b85af0d36',
    'bob-edu-wallet',
    'pending',
    NOW()
)
ON CONFLICT (email) DO NOTHING;
