// Package signing defines the vocabulary that Wallet and the key vault share
// to name keys and sign with them. It holds no secrets and imports neither,
// so both can depend on it. Wallet re-exports the public types under their
// own names.
package signing
