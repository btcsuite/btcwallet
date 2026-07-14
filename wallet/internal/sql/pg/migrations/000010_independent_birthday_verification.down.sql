-- Reintroducing the old constraint requires clearing a retained verification
-- bit when no birthday block is present.
UPDATE wallet_sync_states
SET birthday_block_verified = FALSE
WHERE birthday_block_height IS NULL;

ALTER TABLE wallet_sync_states
ADD CHECK (
    birthday_block_verified = FALSE
    OR birthday_block_height IS NOT NULL
);
