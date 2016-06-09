// Copyright (c) 2015-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package prompt

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/btcsuite/golangcrypto/ssh/terminal"
	"github.com/decred/dcrutil/hdkeychain"
	"github.com/decred/dcrwallet/pgpwordlist"
)

// ProvideSeed is used to prompt for the wallet seed which maybe required during
// upgrades.
func ProvideSeed() ([]byte, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Enter existing wallet seed: ")
		seedStr, err := reader.ReadString('\n')
		if err != nil {
			return nil, err
		}
		seedStr = strings.TrimSpace(strings.ToLower(seedStr))

		seed, err := hex.DecodeString(seedStr)
		if err != nil || len(seed) < hdkeychain.MinSeedBytes ||
			len(seed) > hdkeychain.MaxSeedBytes {

			fmt.Printf("Invalid seed specified.  Must be a "+
				"hexadecimal value that is at least %d bits and "+
				"at most %d bits\n", hdkeychain.MinSeedBytes*8,
				hdkeychain.MaxSeedBytes*8)
			continue
		}

		return seed, nil
	}
}

// ProvidePrivPassphrase is used to prompt for the private passphrase which
// maybe required during upgrades.
func ProvidePrivPassphrase() ([]byte, error) {
	prompt := "Enter the private passphrase of your wallet: "
	for {
		fmt.Print(prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		return pass, nil
	}
}

// promptList prompts the user with the given prefix, list of valid responses,
// and default list entry to use.  The function will repeat the prompt to the
// user until they enter a valid response.
func promptList(reader *bufio.Reader, prefix string, validResponses []string, defaultEntry string) (string, error) {
	// Setup the prompt according to the parameters.
	validStrings := strings.Join(validResponses, "/")
	var prompt string
	if defaultEntry != "" {
		prompt = fmt.Sprintf("%s (%s) [%s]: ", prefix, validStrings,
			defaultEntry)
	} else {
		prompt = fmt.Sprintf("%s (%s): ", prefix, validStrings)
	}

	// Prompt the user until one of the valid responses is given.
	for {
		fmt.Print(prompt)
		reply, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		reply = strings.TrimSpace(strings.ToLower(reply))
		if reply == "" {
			reply = defaultEntry
		}

		for _, validResponse := range validResponses {
			if reply == validResponse {
				return reply, nil
			}
		}
	}
}

// promptListBool prompts the user for a boolean (yes/no) with the given prefix.
// The function will repeat the prompt to the user until they enter a valid
// reponse.
func promptListBool(reader *bufio.Reader, prefix string, defaultEntry string) (bool, error) {
	// Setup the valid responses.
	valid := []string{"n", "no", "y", "yes"}
	response, err := promptList(reader, prefix, valid, defaultEntry)
	if err != nil {
		return false, err
	}
	return response == "yes" || response == "y", nil
}

// PassPrompt prompts the user for a passphrase with the given prefix.  The
// function will ask the user to confirm the passphrase and will repeat the
// prompts until they enter a matching response.
func PassPrompt(reader *bufio.Reader, prefix string, confirm bool) ([]byte, error) {
	// Prompt the user until they enter a passphrase.
	prompt := fmt.Sprintf("%s: ", prefix)
	for {
		fmt.Print(prompt)
		pass, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		pass = bytes.TrimSpace(pass)
		if len(pass) == 0 {
			continue
		}

		if !confirm {
			return pass, nil
		}

		fmt.Print("Confirm passphrase: ")
		confirm, err := terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return nil, err
		}
		fmt.Print("\n")
		confirm = bytes.TrimSpace(confirm)
		if !bytes.Equal(pass, confirm) {
			fmt.Println("The entered passphrases do not match")
			continue
		}

		return pass, nil
	}
}

// PrivatePass prompts the user for a private passphrase.  All prompts are
// repeated until the user enters a valid response.
func PrivatePass(reader *bufio.Reader) ([]byte, error) {
	return PassPrompt(reader, "Enter the private passphrase for your new wallet", true)
}

// PublicPass prompts the user whether they want to add an additional layer of
// encryption to the wallet.  When the user answers yes and there is already a
// public passphrase provided via the passed config, it prompts them whether or
// not to use that configured passphrase.  It will also detect when the same
// passphrase is used for the private and public passphrase and prompt the user
// if they are sure they want to use the same passphrase for both.  Finally, all
// prompts are repeated until the user enters a valid response.
func PublicPass(reader *bufio.Reader, privPass []byte,
	defaultPubPassphrase, configPubPass []byte) ([]byte, error) {

	pubPass := defaultPubPassphrase
	usePubPass, err := promptListBool(reader, "Do you want "+
		"to add an additional layer of encryption for public "+
		"data?", "no")
	if err != nil {
		return nil, err
	}

	if !usePubPass {
		return pubPass, nil
	}

	if len(configPubPass) != 0 && !bytes.Equal(configPubPass, pubPass) {
		useExisting, err := promptListBool(reader, "Use the "+
			"existing configured public passphrase for encryption "+
			"of public data?", "no")
		if err != nil {
			return nil, err
		}

		if useExisting {
			return configPubPass, nil
		}
	}

	for {
		pubPass, err = PassPrompt(reader, "Enter the public "+
			"passphrase for your new wallet", true)
		if err != nil {
			return nil, err
		}

		if bytes.Equal(pubPass, privPass) {
			useSamePass, err := promptListBool(reader,
				"Are you sure want to use the same passphrase "+
					"for public and private data?", "no")
			if err != nil {
				return nil, err
			}

			if useSamePass {
				break
			}

			continue
		}

		break
	}

	fmt.Println("NOTE: Use the --walletpass option to configure your " +
		"public passphrase.")
	return pubPass, nil
}

// Seed prompts the user whether they want to use an existing wallet generation
// seed.  When the user answers no, a seed will be generated and displayed to
// the user along with prompting them for confirmation.  When the user answers
// yes, a the user is prompted for it.  All prompts are repeated until the user
// enters a valid response. The bool returned indicates if the wallet was
// restored from a given seed or not.
func Seed(reader *bufio.Reader) ([]byte, error) {
	// Ascertain the wallet generation seed.
	useUserSeed, err := promptListBool(reader, "Do you have an "+
		"existing wallet seed you want to use?", "no")
	if err != nil {
		return nil, err
	}
	if !useUserSeed {
		seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
		if err != nil {
			return nil, err
		}

		seedStr, err := pgpwordlist.ToStringChecksum(seed)
		if err != nil {
			return nil, err
		}
		seedStrSplit := strings.Split(seedStr, " ")

		fmt.Println("Your wallet generation seed is:")
		for i := 0; i < hdkeychain.RecommendedSeedLen+1; i++ {
			fmt.Printf("%v ", seedStrSplit[i])

			if (i+1)%6 == 0 {
				fmt.Printf("\n")
			}
		}

		fmt.Printf("\n\nHex: %x\n", seed)
		fmt.Println("IMPORTANT: Keep the seed in a safe place as you\n" +
			"will NOT be able to restore your wallet without it.")
		fmt.Println("Please keep in mind that anyone who has access\n" +
			"to the seed can also restore your wallet thereby\n" +
			"giving them access to all your funds, so it is\n" +
			"imperative that you keep it in a secure location.")

		for {
			fmt.Print(`Once you have stored the seed in a safe ` +
				`and secure location, enter "OK" to continue: `)
			confirmSeed, err := reader.ReadString('\n')
			if err != nil {
				return nil, err
			}
			confirmSeed = strings.TrimSpace(confirmSeed)
			confirmSeed = strings.Trim(confirmSeed, `"`)
			if confirmSeed == "OK" {
				break
			}
		}

		return seed, nil
	}

	for {
		fmt.Print("Enter existing wallet seed " +
			"(followed by a blank line): ")

		// Use scanner instead of buffio.Reader so we can choose choose
		// more complicated ending condition rather than just a single
		// newline.
		var seedStr string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				break
			}
			seedStr += " " + line
		}
		seedStrTrimmed := strings.TrimSpace(seedStr)
		seedStrTrimmed = collapseSpace(seedStrTrimmed)
		wordCount := strings.Count(seedStrTrimmed, " ") + 1

		var seed []byte
		if wordCount == 1 {
			if len(seedStrTrimmed)%2 != 0 {
				seedStrTrimmed = "0" + seedStrTrimmed
			}
			seed, err = hex.DecodeString(seedStrTrimmed)
			if err != nil {
				fmt.Printf("Input error: %v\n", err.Error())
			}
		} else {
			seed, err = pgpwordlist.ToBytesChecksum(seedStrTrimmed)
			if err != nil {
				fmt.Printf("Input error: %v\n", err.Error())
			}
		}
		if err != nil || len(seed) < hdkeychain.MinSeedBytes ||
			len(seed) > hdkeychain.MaxSeedBytes {
			fmt.Printf("Invalid seed specified.  Must be a "+
				"word seed (usually 33 words) using the PGP wordlist or "+
				"hexadecimal value that is at least %d bits and "+
				"at most %d bits\n", hdkeychain.MinSeedBytes*8,
				hdkeychain.MaxSeedBytes*8)
			continue
		}

		fmt.Printf("\nSeed input successful. \nHex: %x\n", seed)

		return seed, nil
	}
}

// Setup prompts for, from a buffered reader, the private and/or public
// encryption passphrases to secure a wallet and a previously derived wallet
// seed to use, if any.  privPass and pubPass will always be non-nil values
// (private encryption is required and choosing to not use public data
// encryption will still encrypt the data with an insecure default), and a
// randomly generated seed of the recommended length will be generated and
// returned after the user has confirmed the seed has been backed up to a secure
// location.
//
// The configPubPass parameter is optional (nil should be used to represent the
// lack of a value).  When non-nil, this value represents a public passphrase
// previously specified in a configuration file.  The user will be given the
// option of using this passphrase if public data encryption is enabled,
// otherwise a user-specified passphrase will be prompted for.
func Setup(r *bufio.Reader, insecurePubPass, configPubPass []byte) (privPass, pubPass, seed []byte, err error) {
	// Decred: no legacy keystore restore is needed (first decred wallet
	// version did not use the legacy keystore from earlier versions of
	// btcwallet).

	// Start by prompting for the private passphrase.  When there is an
	// existing keystore, the user will be promped for that passphrase,
	// otherwise they will be prompted for a new one.
	privPass, err = PrivatePass(r)
	if err != nil {
		return
	}

	// Ascertain the public passphrase.  This will either be a value
	// specified by the user or the default hard-coded public passphrase if
	// the user does not want the additional public data encryption.
	pubPass, err = PublicPass(r, privPass, insecurePubPass, configPubPass)
	if err != nil {
		return
	}

	// Ascertain the wallet generation seed.  This will either be an
	// automatically generated value the user has already confirmed or a
	// value the user has entered which has already been validated.
	seed, err = Seed(r)

	return
}

// collapseSpace takes a string and replaces any repeated areas of whitespace
// with a single space character.
func collapseSpace(in string) string {
	whiteSpace := false
	out := ""
	for _, c := range in {
		if unicode.IsSpace(c) {
			if !whiteSpace {
				out = out + " "
			}
			whiteSpace = true
		} else {
			out = out + string(c)
			whiteSpace = false
		}
	}
	return out
}
