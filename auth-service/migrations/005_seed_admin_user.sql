INSERT INTO users (
    user_id, name, email, password_hash, salt, wallet_address, kyc_status, created_at, role
) VALUES (
    '8fb8b6d0-5cc4-4cda-8b63-40e9cf095f44',
    'Network Admin',
    'admin@example.com',
    '796a5c6d82ef9993ab95774f73536e8685f3da7dace0416871e6a90a08466863',
    'salt-admin-example-com',
    'network-admin-wallet',
    'verified',
    NOW(),
    'admin'
)
ON CONFLICT (email) DO NOTHING;
