package wallet

// Signer provides an interface for common, safe cryptographic operations,
// including signing and key derivation.
type Signer interface {
}

// UnsafeSigner provides an interface for security-sensitive cryptographic
// operations that export raw private key material. This interface should be
// used with extreme care and only when absolutely necessary.
type UnsafeSigner interface {
	Signer
}
