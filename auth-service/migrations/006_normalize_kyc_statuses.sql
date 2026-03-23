UPDATE users
SET kyc_status = 'pending_review'
WHERE kyc_status = 'pending';

UPDATE users
SET role = 'user'
WHERE role IS NULL OR role = '';
