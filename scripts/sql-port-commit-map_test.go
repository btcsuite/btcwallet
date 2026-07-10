package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestClassifyPaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		paths []string
		want  string
	}{
		{
			name:  "sql foundation",
			paths: []string{"wallet/internal/sql/sqlite/store.go"},
			want:  "sql-foundation",
		},
		{
			name:  "sqlite store implementation",
			paths: []string{"wallet/internal/db/sqlite/store.go"},
			want:  "reusable-semantic-fix",
		},
		{
			name: "schema plus store implementation",
			paths: []string{
				"wallet/internal/sql/sqlite/queries/accounts.sql",
				"wallet/internal/db/sqlite/accounts.go",
			},
			want: "mixed:reusable-semantic-fix+sql-foundation",
		},
		{
			name:  "public interface",
			paths: []string{"wallet/interface.go"},
			want:  "public-refactor",
		},
		{
			name:  "runtime controller",
			paths: []string{"wallet/controller.go"},
			want:  "runtime-rewrite",
		},
		{
			name:  "existing wallet routing",
			paths: []string{"wallet/wallet.go"},
			want:  "wallet-routing",
		},
		{
			name: "mixed SQL and wallet routing",
			paths: []string{
				"wallet/internal/sql/sqlite/store.go",
				"wallet/wallet.go",
			},
			want: "mixed:sql-foundation+wallet-routing",
		},
		{
			name:  "test tooling",
			paths: []string{"wallet/wallet_test.go"},
			want:  "test-tooling",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := classifyPaths(test.paths); got != test.want {
				t.Fatalf("classifyPaths()=%q, want %q", got, test.want)
			}
		})
	}
}

func TestParseCoAuthors(t *testing.T) {
	t.Parallel()

	const mohamed = "Mohamed Awnallah <mohamedmohey2352@gmail.com>"
	got := parseCoAuthors(mohamed + "\x1f" + mohamed)
	want := []string{mohamed}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("c82d0e co-authors=%q, want %q", got, want)
	}
}

func TestDispositionOverrides(t *testing.T) {
	t.Parallel()

	tests := []struct {
		sha         string
		disposition string
		reason      string
	}{
		{"6bdb0b93fc82223c5ef40bf4750e5761a4895483", "superseded", "source-only: dummy sqlc bootstrap replaced by real schema"},
		{"3ca1e687a29f4853348863cfc97b0fae1f054458", "extract", "Stage 1: retain legacy dual-passphrase and watch-only constraints"},
		{"629858bd7c7731eb2fe52097ada0278a1965bcfb", "defer", "post-port cut: plaintext public metadata design"},
		{"91e133b509e430271be20aef33222409c20cc353", "defer", "post-port cut: derived address-used state rejected by sticky-bit port"},
		{"a3e9b662ea961c9105166c2ff0ff0bb6f63698d9", "defer", "post-port cut: normalized account and address identity rewrite"},
		{"15d51b675fea5816b15c26851f9406eb6b630eee", "defer", "post-port cut: retained tx status and replacement-history ADR"},
		{"1fab2b36e0bff55067e0a7170c848df5c54345b6", "defer", "post-port cut: retained tx status and replacement-history ADR"},
		{"4376c7b89f97bff043bef3796f8c4d333310bea0", "defer", "post-port cut: retained invalidation and tx-status flow"},
		{"5d91700ca8181a2d5a08d299acf3967638e83752", "review", "Stage 2: internal store runtime helper parity review"},
		{"48cb5077fbce74d8335a5f67523ab586ccbf38d8", "review", "Stage 2: internal store write-routing parity review"},
		{"f17b01fa597e69e213dc2371abd5f4ac47fe7698", "review", "Stage 2: internal store read-routing parity review"},
		{"087e1d1fbdc469448599e327d6433f9f8d75255e", "review", "Stage 2: internal store runtime helper parity review"},
		{"772fcb2533c1033a19c6fe2f7df6c808bfacb931", "review", "Stage 2: internal store write-routing parity review"},
		{"2016251b34538ba2983a8176f82b32032e439226", "review", "Stage 2: internal store read-routing parity review"},
		{"c99182afa80614dd905379ff24da04d403b86953", "review", "Stage 2: ApplyTxBatch store parity review"},
		{"2fd48dad77318b264242e6e40a7ab0afc6a4d08d", "review", "Stage 2: ApplyScanBatch store parity review"},
		{"61fca7a3c6d47c4cc37da9f06cb22011b8387b52", "review", "Stage 2: ApplyScanBatch store parity review"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.sha[:8], func(t *testing.T) {
			t.Parallel()
			got, reason := planCommit(
				test.sha, "sql-foundation", 0, "subject", nil,
			)
			if got != test.disposition {
				t.Fatalf("disposition=%q, want %q", got, test.disposition)
			}
			if reason != test.reason {
				t.Fatalf("reason=%q, want %q", reason, test.reason)
			}
		})
	}
}

func TestSQLFoundationRequiresExtraction(t *testing.T) {
	t.Parallel()

	disposition, reason := planCommit(
		"", "sql-foundation", 0, "schema", nil,
	)
	if disposition != "extract" {
		t.Fatalf("disposition=%q, want extract", disposition)
	}
	if reason != "Stage 1: reconstruct SQL foundation against KV parity" {
		t.Fatalf("unexpected reason: %q", reason)
	}
}

func TestReadSourceRefs(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "source_refs.csv")
	data := "name,sha\nmaster,aaa\nsql-wallet,bbb\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	refs, err := readSourceRefs(path)
	if err != nil {
		t.Fatal(err)
	}
	if refs["master"] != "aaa" || refs["sql-wallet"] != "bbb" {
		t.Fatalf("unexpected refs: %v", refs)
	}
}

func TestValidCommitSHA(t *testing.T) {
	t.Parallel()

	if !validCommitSHA("4bd4563e04c7a156c9326b5da8a67ff8ed9dc572") {
		t.Fatal("valid SHA rejected")
	}
	if validCommitSHA("not-a-sha") {
		t.Fatal("invalid SHA accepted")
	}
}
