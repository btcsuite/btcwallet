UPDATE utxo_leases
SET expires_unix = expires_unix / 1000000000;
