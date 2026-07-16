package schemaid

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// salvageFingerprint returns a fresh copy of the pre-marker salvage table set
// so a test can extend it without mutating the package fixture.
func salvageFingerprint() []string {
	return append([]string(nil), salvageTables...)
}

// TestSchemaIdentityEvaluate verifies that the pure classification maps every
// database shape to the correct action or typed rejection error without any
// database access.
func TestSchemaIdentityEvaluate(t *testing.T) {
	t.Parallel()

	marked := func(family string, generation int64) *Marker {
		return &Marker{Family: family, Generation: generation}
	}

	testCases := []struct {
		name       string
		tables     []string
		marker     *Marker
		dirty      bool
		wantAction Action
		wantErr    error
	}{
		{
			name:       "empty database bootstraps",
			tables:     nil,
			wantAction: ActionBootstrap,
		},
		{
			name:       "only migration table bootstraps",
			tables:     []string{migrationTable},
			wantAction: ActionBootstrap,
		},
		{
			name:    "empty dirty database rejected",
			tables:  []string{migrationTable},
			dirty:   true,
			wantErr: ErrDirtySchema,
		},
		{
			name: "known pre-marker salvage backfills",
			tables: append(
				salvageFingerprint(), migrationTable,
			),
			wantAction: ActionBackfill,
		},
		{
			name: "identity table without row backfills",
			tables: append(
				salvageFingerprint(), migrationTable, IdentityTable,
			),
			wantAction: ActionBackfill,
		},
		{
			name:    "foreign utxos table rejected",
			tables:  []string{"utxos"},
			wantErr: ErrForeignSchemaFamily,
		},
		{
			name: "normalized schema rejected as foreign",
			tables: append(
				salvageFingerprint(), "utxos", "tx_replacements",
			),
			wantErr: ErrForeignSchemaFamily,
		},
		{
			name:    "foreign table rejected before dirty",
			tables:  []string{"utxos"},
			dirty:   true,
			wantErr: ErrForeignSchemaFamily,
		},
		{
			name:    "unknown single table rejected",
			tables:  []string{"random_table"},
			wantErr: ErrUnknownSchema,
		},
		{
			name:    "partial salvage rejected as unknown",
			tables:  []string{"blocks", "wallets"},
			wantErr: ErrUnknownSchema,
		},
		{
			name:    "dirty in-progress salvage rejected",
			tables:  []string{"blocks", "wallets", migrationTable},
			dirty:   true,
			wantErr: ErrDirtySchema,
		},
		{
			name:       "valid marker validates only",
			tables:     append(salvageFingerprint(), IdentityTable),
			marker:     marked(Family, Generation),
			wantAction: ActionValidateOnly,
		},
		{
			name:    "marked foreign family rejected",
			tables:  []string{IdentityTable},
			marker:  marked("other-family", Generation),
			wantErr: ErrForeignSchemaFamily,
		},
		{
			name:    "marked dirty rejected",
			tables:  append(salvageFingerprint(), IdentityTable),
			marker:  marked(Family, Generation),
			dirty:   true,
			wantErr: ErrDirtySchema,
		},
		{
			name:    "marked newer generation rejected",
			tables:  []string{IdentityTable},
			marker:  marked(Family, Generation+1),
			wantErr: ErrNewerGeneration,
		},
		{
			name:    "marked unsupported generation rejected",
			tables:  []string{IdentityTable},
			marker:  marked(Family, MinGeneration-1),
			wantErr: ErrUnsupportedGeneration,
		},
		{
			name:    "marked foreign family beats newer generation",
			tables:  []string{IdentityTable},
			marker:  marked("other-family", Generation+1),
			wantErr: ErrForeignSchemaFamily,
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			action, err := Evaluate(tc.tables, tc.marker, tc.dirty)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.wantAction, action)
		})
	}
}
