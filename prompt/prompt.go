package prompt

import (
	"bufio"

	"github.com/decred/dcrwallet/internal/prompt"
	"github.com/decred/dcrwallet/wallet"
)

// Setup prompts for, from a buffered reader, the private and/or public
// encryption passphrases to secure a wallet and a previously derived wallet
// seed to use, if any.  privPass and pubPass will always be non-nil values
// (private encryption is required and choosing to not use public data
// encryption will still encrypt the data with an insecure default), and a
// randomly generated seed of the recommended length will be generated and
// returned after the user has confirmed the seed has been backed up to a secure
// location.
func Setup(r *bufio.Reader) (privPass, pubPass, seed []byte, err error) {
	return prompt.Setup(r, []byte(wallet.InsecurePubPassphrase), nil)
}
