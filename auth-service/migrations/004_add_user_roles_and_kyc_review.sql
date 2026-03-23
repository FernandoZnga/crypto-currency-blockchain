ALTER TABLE users
ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

ALTER TABLE kyc_submissions
ADD COLUMN IF NOT EXISTS review_note TEXT;

ALTER TABLE kyc_submissions
ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

ALTER TABLE kyc_submissions
ADD COLUMN IF NOT EXISTS reviewed_by_user_id UUID REFERENCES users (user_id);
