ALTER TABLE kyc_submissions
ADD COLUMN IF NOT EXISTS anchor_hash TEXT;

ALTER TABLE kyc_submissions
ADD COLUMN IF NOT EXISTS anchor_tx_id TEXT;
