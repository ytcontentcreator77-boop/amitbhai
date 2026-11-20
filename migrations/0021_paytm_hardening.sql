-- Enforce one INR ledger credit per Paytm payment record.
CREATE UNIQUE INDEX IF NOT EXISTS idx_paytm_inr_ledger_once
ON inr_ledger(ref)
WHERE kind='paytm_topup';
