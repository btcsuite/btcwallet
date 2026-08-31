package keyvault

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestChangePassphraseParamsValidate verifies that rotation requests reject a
// missing selection or an incomplete private passphrase pair.
func TestChangePassphraseParamsValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		params      ChangePassphraseParams
		wantContext string
	}{
		{
			name:        "no rotation",
			wantContext: "no passphrase selected",
		},
		{
			name: "empty private pair",
			params: ChangePassphraseParams{
				PrivateOld: []byte{},
				PrivateNew: []byte{},
			},
			wantContext: "private old passphrase",
		},
		{
			name: "private old without new",
			params: ChangePassphraseParams{
				PrivateOld: []byte("old-private"),
			},
			wantContext: "private new passphrase",
		},
		{
			name: "private new without old",
			params: ChangePassphraseParams{
				PrivateNew: []byte("new-private"),
			},
			wantContext: "private old passphrase",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := test.params.Validate()
			require.ErrorIs(t, err, ErrEmptyPassphrase)
			require.ErrorContains(t, err, test.wantContext)
		})
	}
}

// TestChangePassphraseParamsValidateSuccess verifies that supported rotation
// selections pass backend-neutral validation.
func TestChangePassphraseParamsValidateSuccess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		params ChangePassphraseParams
	}{
		{
			name: "public rotation",
			params: ChangePassphraseParams{
				PublicOld: []byte("old-public"),
				PublicNew: []byte("new-public"),
			},
		},
		{
			name: "public rotation from empty",
			params: ChangePassphraseParams{
				PublicOld: []byte{},
				PublicNew: []byte("new-public"),
			},
		},
		{
			name: "public rotation to empty",
			params: ChangePassphraseParams{
				PublicOld: []byte("old-public"),
				PublicNew: []byte{},
			},
		},
		{
			name: "empty public rotation",
			params: ChangePassphraseParams{
				PublicOld: []byte{},
				PublicNew: []byte{},
			},
		},
		{
			name: "private rotation",
			params: ChangePassphraseParams{
				PrivateOld: []byte("old-private"),
				PrivateNew: []byte("new-private"),
			},
		},
		{
			name: "combined rotation",
			params: ChangePassphraseParams{
				PublicOld:  []byte("old-public"),
				PublicNew:  []byte("new-public"),
				PrivateOld: []byte("old-private"),
				PrivateNew: []byte("new-private"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			require.NoError(t, test.params.Validate())
		})
	}
}
