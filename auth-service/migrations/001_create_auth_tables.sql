CREATE TABLE IF NOT EXISTS users (
    user_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    wallet_address TEXT NOT NULL,
    kyc_status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (user_id),
    created_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS kyc_submissions (
    submission_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (user_id),
    document_type TEXT NOT NULL,
    country TEXT NOT NULL,
    note TEXT NOT NULL,
    submitted_at TIMESTAMPTZ NOT NULL,
    status TEXT NOT NULL
);
