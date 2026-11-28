-- This pragma enables WAL after identity succeeds and returns the effective
-- mode; startup accepts only "wal" so unsupported filesystems fail closed.
PRAGMA journal_mode = WAL;
