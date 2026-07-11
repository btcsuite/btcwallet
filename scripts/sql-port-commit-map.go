// sql-port-commit-map generates the Stage 0 commit attribution map.
package main

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	expectedCommitNum = 969
	associationBatch  = 30
	prCommitBatch     = 15
)

type commit struct {
	sha         string
	authorName  string
	authorEmail string
	coAuthors   []string
	authorDate  string
	subject     string
	paths       []string
	associated  []pullRequest
}

type dispositionOverride struct {
	disposition string
	destination string
}

var dispositionOverrides = map[string]dispositionOverride{
	"15d51b675fea5816b15c26851f9406eb6b630eee": {
		"defer", "post-port cut: retained tx status and replacement-history ADR",
	},
	"1fab2b36e0bff55067e0a7170c848df5c54345b6": {
		"defer", "post-port cut: retained tx status and replacement-history ADR",
	},
	"4376c7b89f97bff043bef3796f8c4d333310bea0": {
		"defer", "post-port cut: retained invalidation and tx-status flow",
	},
	"4c4fed6dcebdc3f460f278091d96ddac7685a042": {
		"defer", "post-port cut: retained transaction replacement queries",
	},
	"6bdb0b93fc82223c5ef40bf4750e5761a4895483": {
		"superseded", "source-only: dummy sqlc bootstrap replaced by real schema",
	},
	"a72584da266061a8d2df2b3b4d99ed5416f57cd7": {
		"superseded", "source-only: generated dummy sqlc bootstrap replaced by real schema",
	},
	"c2e5c267f41ad6e0e67fde7d57331b1522827180": {
		"superseded", "source-only: dummy sqlc cleanup consumed by real schema",
	},
	"3ca1e687a29f4853348863cfc97b0fae1f054458": {
		"extract", "Stage 1: retain legacy dual-passphrase and watch-only constraints",
	},
	"629858bd7c7731eb2fe52097ada0278a1965bcfb": {
		"defer", "post-port cut: plaintext public metadata design",
	},
	"2e661250e0d67ee067aba39432d514d131fce54e": {
		"defer", "post-port cut: plaintext public metadata design",
	},
	"7a387863766ab69b5ea516073d20e20acc7b18ac": {
		"defer", "post-port cut: plaintext public metadata design",
	},
	"91e133b509e430271be20aef33222409c20cc353": {
		"defer", "post-port cut: derived address-used state rejected by sticky-bit port",
	},
	"a3e9b662ea961c9105166c2ff0ff0bb6f63698d9": {
		"defer", "post-port cut: normalized account and address identity rewrite",
	},
	"ab9494381952fb8cf128e16f96f436329522b8d1": {
		"defer", "post-port cut: normalized account and address identity rewrite",
	},
	"a28521c31c123ab08b191a1941f77248c757461e": {
		"defer", "post-port cut: normalized account and address identity rewrite",
	},
	"0b9e4a897c27eb86d94ac3a679a6c4fce48d3f65": {
		"defer", "post-port cut: normalized account and address identity rewrite",
	},
	"1a0eadbd3c343dc138ce2bbf3b9a33f58dc21427": {
		"defer", "post-port cut: normalized account and address identity rewrite",
	},
	"5d91700ca8181a2d5a08d299acf3967638e83752": {
		"review", "Stage 2: internal store runtime helper parity review",
	},
	"48cb5077fbce74d8335a5f67523ab586ccbf38d8": {
		"review", "Stage 2: internal store write-routing parity review",
	},
	"f17b01fa597e69e213dc2371abd5f4ac47fe7698": {
		"review", "Stage 2: internal store read-routing parity review",
	},
	"087e1d1fbdc469448599e327d6433f9f8d75255e": {
		"review", "Stage 2: internal store runtime helper parity review",
	},
	"772fcb2533c1033a19c6fe2f7df6c808bfacb931": {
		"review", "Stage 2: internal store write-routing parity review",
	},
	"2016251b34538ba2983a8176f82b32032e439226": {
		"review", "Stage 2: internal store read-routing parity review",
	},
	"c99182afa80614dd905379ff24da04d403b86953": {
		"review", "Stage 2: ApplyTxBatch store parity review",
	},
	"2fd48dad77318b264242e6e40a7ab0afc6a4d08d": {
		"review", "Stage 2: ApplyScanBatch store parity review",
	},
	"61fca7a3c6d47c4cc37da9f06cb22011b8387b52": {
		"review", "Stage 2: ApplyScanBatch store parity review",
	},
}

type pullRequest struct {
	Number   int    `json:"number"`
	State    string `json:"state"`
	MergedAt string `json:"mergedAt"`
	ClosedAt string `json:"closedAt"`
}

type prInventoryEntry struct {
	state  string
	action string
}

type prCommitConnection struct {
	TotalCount int `json:"totalCount"`
	PageInfo   struct {
		HasNextPage bool `json:"hasNextPage"`
	} `json:"pageInfo"`
	Nodes []struct {
		Commit struct {
			OID string `json:"oid"`
		} `json:"commit"`
	} `json:"nodes"`
}

type prCommitObject struct {
	Number   int                `json:"number"`
	State    string             `json:"state"`
	MergedAt string             `json:"mergedAt"`
	ClosedAt string             `json:"closedAt"`
	Commits  prCommitConnection `json:"commits"`
}

type associationConnection struct {
	TotalCount int `json:"totalCount"`
	PageInfo   struct {
		HasNextPage bool `json:"hasNextPage"`
	} `json:"pageInfo"`
	Nodes []pullRequest `json:"nodes"`
}

type commitObject struct {
	Associated associationConnection `json:"associatedPullRequests"`
}

type graphqlResponse struct {
	Data struct {
		Repository map[string]json.RawMessage `json:"repository"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func main() {
	var (
		base = flag.String("base", "", "base ref; defaults to pinned master SHA")
		head = flag.String("head", "", "head ref; defaults to pinned sql-wallet SHA")
		mode = flag.String("mode", "verify", "verify committed snapshot or refresh live attribution")
		refs = flag.String(
			"source-refs",
			"docs/developer/sql_port_inventory/source_refs.csv",
			"frozen source refs CSV",
		)
		prs = flag.String(
			"pr-inventory",
			"docs/developer/sql_port_inventory/pr_inventory.csv",
			"PR inventory CSV",
		)
		out = flag.String(
			"out", "docs/developer/sql_port_inventory/commit_map.csv",
			"output CSV",
		)
	)
	flag.Parse()

	root, err := gitOutput(".", "rev-parse", "--show-toplevel")
	check(err)
	pinned, err := readSourceRefs(filepath.Join(root, *refs))
	check(err)
	if *base == "" {
		*base = pinned["master"]
	}
	if *head == "" {
		*head = pinned["sql-wallet"]
	}
	if *base == "" || *head == "" {
		check(errors.New("source refs must pin master and sql-wallet"))
	}
	prInventory, err := readPRInventory(
		filepath.Join(root, *prs),
	)
	check(err)
	commits, err := readCommits(root, *base, *head)
	check(err)
	if len(commits) != expectedCommitNum {
		check(fmt.Errorf(
			"expected %d commits in %s..%s, found %d",
			expectedCommitNum, *base, *head, len(commits),
		))
	}

	check(loadPaths(root, commits))
	check(loadCoAuthors(root, commits))
	if *mode == "verify" {
		check(verifyCommitMap(filepath.Join(root, *out), commits, prInventory))
		fmt.Printf("verified %s against %s..%s with %d commits\n",
			filepath.Join(root, *out), *base, *head, len(commits))
		return
	}
	if *mode != "live" {
		check(fmt.Errorf("unknown mode %q: use verify or live", *mode))
	}
	check(loadAssociations(root, commits, prInventory))
	exactMembership, err := loadPRCommitMembership(root, prInventory)
	check(err)
	check(writeCommitMap(
		filepath.Join(root, *out), commits, prInventory,
		exactMembership,
	))

	fmt.Printf("wrote %s with %d commits\n", filepath.Join(root, *out),
		len(commits))
}

func readSourceRefs(path string) (map[string]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("empty source refs: %s", path)
	}
	headers := make(map[string]int)
	for index, header := range rows[0] {
		headers[header] = index
	}
	name, hasName := headers["name"]
	sha, hasSHA := headers["sha"]
	if !hasName || !hasSHA {
		return nil, errors.New("source refs must contain name and sha columns")
	}
	refs := make(map[string]string)
	for _, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			return nil, fmt.Errorf("malformed source refs row")
		}
		refs[row[name]] = row[sha]
	}
	return refs, nil
}

func readPRInventory(path string) (map[int]prInventoryEntry, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) < 2 {
		return nil, fmt.Errorf("empty PR inventory: %s", path)
	}
	headers := make(map[string]int)
	for index, header := range rows[0] {
		headers[header] = index
	}
	for _, required := range []string{
		"number", "state", "port_first_action",
	} {
		if _, ok := headers[required]; !ok {
			return nil, fmt.Errorf("missing PR column %s", required)
		}
	}

	inventory := make(map[int]prInventoryEntry)
	for _, row := range rows[1:] {
		if len(row) != len(rows[0]) {
			return nil, fmt.Errorf(
				"malformed PR inventory row: got %d columns, want %d",
				len(row), len(rows[0]),
			)
		}
		number, err := strconv.Atoi(row[headers["number"]])
		if err != nil {
			return nil, err
		}
		entry := prInventoryEntry{
			state:  row[headers["state"]],
			action: row[headers["port_first_action"]],
		}
		inventory[number] = entry
	}
	return inventory, nil
}

func readCommits(root, base, head string) ([]*commit, error) {
	format := "%H%x09%an%x09%ae%x09%aI%x09%s"
	output, err := gitOutput(
		root, "log", "--reverse", "--format="+format, base+".."+head,
	)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(output, "\n")
	commits := make([]*commit, 0, len(lines))
	seen := make(map[string]struct{})
	for _, line := range lines {
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "\t", 5)
		if len(fields) != 5 {
			return nil, fmt.Errorf("malformed git log row: %q", line)
		}
		if _, ok := seen[fields[0]]; ok {
			return nil, fmt.Errorf("duplicate commit %s", fields[0])
		}
		seen[fields[0]] = struct{}{}
		commits = append(commits, &commit{
			sha:         fields[0],
			authorName:  fields[1],
			authorEmail: fields[2],
			authorDate:  fields[3],
			subject:     fields[4],
		})
	}
	return commits, nil
}

func loadPaths(root string, commits []*commit) error {
	for _, item := range commits {
		output, err := gitOutput(
			root, "diff-tree", "--no-commit-id", "--name-only", "-r",
			item.sha,
		)
		if err != nil {
			return err
		}
		if output != "" {
			item.paths = strings.Split(output, "\n")
			sort.Strings(item.paths)
		}
	}
	return nil
}

func loadCoAuthors(root string, commits []*commit) error {
	for _, item := range commits {
		output, err := gitOutput(
			root, "show", "-s",
			"--format=%(trailers:key=Co-authored-by,valueonly,separator=%x1f)",
			item.sha,
		)
		if err != nil {
			return err
		}
		item.coAuthors = parseCoAuthors(output)
	}
	return nil
}

func parseCoAuthors(value string) []string {
	seen := make(map[string]struct{})
	for _, author := range strings.Split(value, "\x1f") {
		author = strings.TrimSpace(author)
		if author != "" {
			seen[author] = struct{}{}
		}
	}
	authors := make([]string, 0, len(seen))
	for author := range seen {
		authors = append(authors, author)
	}
	sort.Strings(authors)
	return authors
}

func loadAssociations(root string, commits []*commit,
	inventory map[int]prInventoryEntry) error {

	for start := 0; start < len(commits); start += associationBatch {
		end := start + associationBatch
		if end > len(commits) {
			end = len(commits)
		}

		var query strings.Builder
		query.WriteString("query { repository(owner:\"btcsuite\", name:\"btcwallet\") {")
		for index, item := range commits[start:end] {
			if !validCommitSHA(item.sha) {
				return fmt.Errorf("invalid commit SHA %q", item.sha)
			}
			fmt.Fprintf(
				&query,
				"c%d: object(oid:\"%s\") { ... on Commit { "+
					"associatedPullRequests(first:100) { totalCount "+
					"pageInfo { hasNextPage } nodes { number state "+
					"mergedAt closedAt } } } } ",
				index, item.sha,
			)
		}
		query.WriteString("} }")

		output, err := commandOutput(
			root, "gh", "api", "graphql", "-f", "query="+query.String(),
		)
		if err != nil {
			return err
		}
		var response graphqlResponse
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			return err
		}
		if len(response.Errors) != 0 {
			return fmt.Errorf("GraphQL error: %s", response.Errors[0].Message)
		}

		for index, item := range commits[start:end] {
			raw, ok := response.Data.Repository[fmt.Sprintf("c%d", index)]
			if !ok || bytes.Equal(raw, []byte("null")) {
				return fmt.Errorf("commit %s missing from GitHub", item.sha)
			}
			var object commitObject
			if err := json.Unmarshal(raw, &object); err != nil {
				return err
			}
			if object.Associated.PageInfo.HasNextPage ||
				object.Associated.TotalCount > 100 {

				return fmt.Errorf(
					"commit %s has more than 100 associated PRs", item.sha,
				)
			}
			for _, pr := range object.Associated.Nodes {
				if _, ok := inventory[pr.Number]; ok {
					item.associated = append(item.associated, pr)
				}
			}
		}
	}
	return nil
}

func loadPRCommitMembership(root string,
	inventory map[int]prInventoryEntry) (map[string][]pullRequest, error) {

	numbers := make([]int, 0, len(inventory))
	for number := range inventory {
		if number != 1083 && number != 1110 {
			numbers = append(numbers, number)
		}
	}
	sort.Ints(numbers)
	membership := make(map[string][]pullRequest)
	for start := 0; start < len(numbers); start += prCommitBatch {
		end := start + prCommitBatch
		if end > len(numbers) {
			end = len(numbers)
		}
		var query strings.Builder
		query.WriteString("query { repository(owner:\"btcsuite\", name:\"btcwallet\") {")
		for index, number := range numbers[start:end] {
			fmt.Fprintf(
				&query,
				"p%d: pullRequest(number:%d) { number state mergedAt "+
					"closedAt commits(first:100) { totalCount pageInfo "+
					"{ hasNextPage } nodes { commit { oid } } } } ",
				index, number,
			)
		}
		query.WriteString("} }")
		output, err := commandOutput(
			root, "gh", "api", "graphql", "-f", "query="+query.String(),
		)
		if err != nil {
			return nil, err
		}
		var response graphqlResponse
		if err := json.Unmarshal([]byte(output), &response); err != nil {
			return nil, err
		}
		if len(response.Errors) != 0 {
			return nil, fmt.Errorf(
				"GraphQL error: %s", response.Errors[0].Message,
			)
		}
		for index, number := range numbers[start:end] {
			raw, ok := response.Data.Repository[fmt.Sprintf("p%d", index)]
			if !ok || bytes.Equal(raw, []byte("null")) {
				return nil, fmt.Errorf("PR #%d missing from GitHub", number)
			}
			var object prCommitObject
			if err := json.Unmarshal(raw, &object); err != nil {
				return nil, err
			}
			if object.Commits.PageInfo.HasNextPage ||
				object.Commits.TotalCount > 100 {

				fmt.Fprintf(
					os.Stderr, "skipping broad PR #%d commit list (%d commits)\n",
					number, object.Commits.TotalCount,
				)
				continue
			}
			pr := pullRequest{
				Number:   object.Number,
				State:    object.State,
				MergedAt: object.MergedAt,
				ClosedAt: object.ClosedAt,
			}
			for _, node := range object.Commits.Nodes {
				membership[node.Commit.OID] = append(
					membership[node.Commit.OID], pr,
				)
			}
		}
	}
	return membership, nil
}

func writeCommitMap(path string, commits []*commit,
	inventory map[int]prInventoryEntry,
	exactMembership map[string][]pullRequest) error {

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	if err := writer.Write([]string{
		"commit", "author_name", "author_email", "co_authors", "author_date", "subject",
		"canonical_pr", "canonical_pr_source", "related_prs",
		"path_category", "changed_path_count", "changed_paths",
		"planned_disposition", "destination_stage_cut",
	}); err != nil {
		return err
	}

	for _, item := range commits {
		exact := exactMembership[item.sha]
		canonical, source := canonicalPR(item, exact)
		related := relatedPRs(item, exact, canonical)
		category := classifyPaths(item.paths)
		if item.sha == "90eaaccf27a0b4f95fed7fe4f8039cc34693566f" {
			category = "rebase-marker"
		}
		disposition, destination := planCommit(
			item.sha, category, canonical, item.subject, inventory,
		)
		canonicalValue := "unresolved"
		if canonical != 0 {
			canonicalValue = fmt.Sprintf("#%d", canonical)
		}
		if err := writer.Write([]string{
			item.sha,
			item.authorName,
			item.authorEmail,
			strings.Join(item.coAuthors, ";"),
			item.authorDate,
			item.subject,
			canonicalValue,
			source,
			related,
			category,
			strconv.Itoa(len(item.paths)),
			strings.Join(item.paths, ";"),
			disposition,
			destination,
		}); err != nil {
			return err
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		return err
	}
	return file.Sync()
}

func verifyCommitMap(path string, commits []*commit,
	inventory map[int]prInventoryEntry) error {

	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	rows, err := csv.NewReader(file).ReadAll()
	if err != nil {
		return err
	}
	if len(rows) != len(commits)+1 {
		return fmt.Errorf("snapshot has %d rows, want %d", len(rows)-1, len(commits))
	}
	headers := make(map[string]int)
	for index, header := range rows[0] {
		headers[header] = index
	}
	required := []string{"commit", "author_name", "author_email", "co_authors", "author_date", "subject", "path_category", "changed_path_count", "changed_paths", "planned_disposition", "destination_stage_cut"}
	for _, column := range required {
		if _, ok := headers[column]; !ok {
			return fmt.Errorf("snapshot missing column %s", column)
		}
	}
	for index, item := range commits {
		row := rows[index+1]
		category := classifyPaths(item.paths)
		if item.sha == "90eaaccf27a0b4f95fed7fe4f8039cc34693566f" {
			category = "rebase-marker"
		}
		canonical := 0
		if value := row[headers["canonical_pr"]]; value != "unresolved" {
			canonical, err = strconv.Atoi(strings.TrimPrefix(value, "#"))
			if err != nil {
				return err
			}
		}
		disposition, destination := planCommit(item.sha, category, canonical, item.subject, inventory)
		want := map[string]string{
			"commit": item.sha, "author_name": item.authorName,
			"author_email": item.authorEmail,
			"co_authors":   strings.Join(item.coAuthors, ";"),
			"author_date":  item.authorDate, "subject": item.subject,
			"path_category":         category,
			"changed_path_count":    strconv.Itoa(len(item.paths)),
			"changed_paths":         strings.Join(item.paths, ";"),
			"planned_disposition":   disposition,
			"destination_stage_cut": destination,
		}
		for column, value := range want {
			if row[headers[column]] != value {
				return fmt.Errorf("snapshot commit %s column %s=%q, want %q", item.sha, column, row[headers[column]], value)
			}
		}
	}
	return nil
}

func canonicalPR(item *commit, exact []pullRequest) (int, string) {
	for _, state := range []string{"MERGED", "CLOSED", "OPEN"} {
		var candidates []pullRequest
		for _, pr := range exact {
			if pr.State == state {
				candidates = append(candidates, pr)
			}
		}
		if len(candidates) == 0 {
			continue
		}
		switch state {
		case "MERGED":
			sortPullRequests(candidates, func(pr pullRequest) string {
				return pr.MergedAt
			})
			return candidates[0].Number, "exact-pr-commit-list-merged"
		case "CLOSED":
			sortPullRequests(candidates, func(pr pullRequest) string {
				return pr.ClosedAt
			})
			return candidates[0].Number, "exact-pr-commit-list-closed"
		case "OPEN":
			sort.Slice(candidates, func(i, j int) bool {
				return candidates[i].Number < candidates[j].Number
			})
			return candidates[0].Number, "exact-pr-commit-list-open"
		}
	}

	var merged, closed []pullRequest
	for _, pr := range item.associated {
		if pr.Number == 1083 || pr.Number == 1110 {
			continue
		}
		switch pr.State {
		case "MERGED":
			merged = append(merged, pr)
		case "CLOSED":
			closed = append(closed, pr)
		}
	}
	if len(merged) != 0 {
		sortPullRequests(merged, func(pr pullRequest) string {
			return pr.MergedAt
		})
		return merged[0].Number, "github-associated-merged"
	}
	if len(closed) != 0 {
		sortPullRequests(closed, func(pr pullRequest) string {
			return pr.ClosedAt
		})
		return closed[0].Number, "github-associated-closed"
	}
	return 0, "unresolved"
}

func sortPullRequests(prs []pullRequest, date func(pullRequest) string) {
	sort.Slice(prs, func(i, j int) bool {
		left, right := date(prs[i]), date(prs[j])
		if left == right {
			return prs[i].Number < prs[j].Number
		}
		if left == "" {
			return false
		}
		if right == "" {
			return true
		}
		leftTime, leftErr := time.Parse(time.RFC3339, left)
		rightTime, rightErr := time.Parse(time.RFC3339, right)
		if leftErr != nil || rightErr != nil {
			return left < right
		}
		return leftTime.Before(rightTime)
	})
}

func relatedPRs(item *commit, exact []pullRequest, canonical int) string {
	numbers := make(map[int]struct{})
	for _, pr := range item.associated {
		numbers[pr.Number] = struct{}{}
	}
	for _, pr := range exact {
		numbers[pr.Number] = struct{}{}
	}
	delete(numbers, canonical)
	ordered := make([]int, 0, len(numbers))
	for number := range numbers {
		ordered = append(ordered, number)
	}
	sort.Ints(ordered)
	if len(ordered) == 0 {
		return "none"
	}
	values := make([]string, 0, len(ordered))
	for _, number := range ordered {
		values = append(values, fmt.Sprintf("#%d", number))
	}
	return strings.Join(values, ";")
}

func classifyPaths(paths []string) string {
	classes := make(map[string]struct{})
	for _, path := range paths {
		lower := strings.ToLower(path)
		special := false
		isTest := strings.HasSuffix(lower, "_test.go") ||
			strings.HasPrefix(lower, "docs/") ||
			strings.HasPrefix(lower, ".github/") ||
			strings.HasPrefix(lower, "scripts/") ||
			strings.HasPrefix(lower, "make/") ||
			lower == "makefile" || lower == "go.mod" || lower == "go.sum"

		if strings.Contains(lower, "keyvault") ||
			strings.Contains(lower, "key_vault") ||
			strings.Contains(lower, "getsecret") ||
			strings.Contains(lower, "walletsecrets") ||
			strings.Contains(lower, "encryption") ||
			strings.Contains(lower, "xchacha") ||
			strings.Contains(lower, "single-passphrase") {

			classes["key-vault-signing-rewrite"] = struct{}{}
			special = true
		}
		if strings.HasPrefix(lower, "wallet/internal/sql/") ||
			strings.Contains(lower, "sqlc") ||
			strings.HasSuffix(lower, ".sql") ||
			lower == "sqlc.yaml" || lower == ".sqlfluff" ||
			strings.Contains(lower, "0006-wtxmgr-sql-schema") {

			classes["sql-foundation"] = struct{}{}
			special = true
		}
		if strings.HasPrefix(lower, "wallet/internal/db/") {

			classes["reusable-semantic-fix"] = struct{}{}
			special = true
		}

		base := strings.TrimSuffix(filepath.Base(lower), "_test.go")
		base = strings.TrimSuffix(base, ".go")
		walletRootFile := strings.HasPrefix(lower, "wallet/") &&
			strings.Count(lower, "/") == 1
		if (walletRootFile || lower == "waddrmgr/interface.go" ||
			lower == "wtxmgr/interface.go") && containsString([]string{
			"interface", "account_manager", "address_manager",
			"psbt_manager", "signer", "tx_creator", "tx_publisher",
			"tx_reader", "tx_writer", "utxo_manager", "deprecated",
			"unstable",
		}, base) {
			classes["public-refactor"] = struct{}{}
			special = true
		}
		if (walletRootFile && containsString([]string{
			"controller", "manager", "syncer", "state", "rescan",
			"recovery", "chainntfns",
		}, base)) || strings.Contains(lower, "controller-syncer") ||
			strings.Contains(lower, "scanning_sync_architecture") ||
			strings.Contains(lower, "0003-optimistic-cfilter") ||
			strings.Contains(lower, "0004-targeted-rescan") ||
			strings.Contains(lower, "0005-no-auto-rescan") {

			classes["runtime-rewrite"] = struct{}{}
			special = true
		}

		if isTest {
			classes["test-tooling"] = struct{}{}
			continue
		}
		isWalletProduction := strings.HasSuffix(lower, ".go") &&
			(strings.HasPrefix(lower, "wallet/") ||
				strings.HasPrefix(lower, "waddrmgr/") ||
				strings.HasPrefix(lower, "wtxmgr/"))
		if isWalletProduction && !special {
			classes["wallet-routing"] = struct{}{}
		}
		if strings.HasPrefix(lower, "chain/") &&
			strings.HasSuffix(lower, ".go") {

			classes["runtime-rewrite"] = struct{}{}
		}
	}

	delete(classes, "test-tooling")
	if len(classes) == 0 {
		if len(paths) == 0 {
			return "unclassified"
		}
		return "test-tooling"
	}
	ordered := make([]string, 0, len(classes))
	for class := range classes {
		ordered = append(ordered, class)
	}
	sort.Strings(ordered)
	if len(ordered) == 1 {
		return ordered[0]
	}
	return "mixed:" + strings.Join(ordered, "+")
}

func validCommitSHA(sha string) bool {
	if len(sha) != 40 {
		return false
	}

	decoded, err := hex.DecodeString(sha)
	return err == nil && len(decoded) == 20
}

func planCommit(sha, category string, canonical int, subject string,
	inventory map[int]prInventoryEntry) (string, string) {

	if override, ok := dispositionOverrides[sha]; ok {
		return override.disposition, override.destination
	}
	if canonical != 0 && inventory[canonical].action == "source-only" {
		return "superseded", "source-only: canonical feeder superseded"
	}
	switch category {
	case "sql-foundation":
		return "extract", "Stage 1: reconstruct SQL foundation against KV parity"
	case "reusable-semantic-fix":
		return "review", "Stage 2: internal store parity review"
	case "wallet-routing":
		return "extract", "Stage 3: rework behind current wallet facade"
	case "public-refactor":
		return "defer", "post-port cut: public role interfaces"
	case "runtime-rewrite":
		return "defer", "post-port cut: controller and syncer runtime"
	case "key-vault-signing-rewrite":
		return "defer", "post-port cut: key vault and signer redesign"
	case "test-tooling":
		lower := strings.ToLower(subject)
		if strings.Contains(lower, "sql") || strings.Contains(lower, "db") ||
			strings.Contains(lower, "schema") {

			return "review", "Stage 1: supporting test and tooling review"
		}
		return "review", "Stage 0: manual relevance review"
	case "unclassified":
		return "review", "Stage 0: unclassified path review"
	case "rebase-marker":
		return "superseded", "source-only: empty SQL branch rebase marker"
	}

	if strings.HasPrefix(category, "mixed:") {
		deferredOnly := true
		for _, class := range strings.Split(
			strings.TrimPrefix(category, "mixed:"), "+",
		) {
			switch class {
			case "public-refactor", "runtime-rewrite",
				"key-vault-signing-rewrite":
			default:
				deferredOnly = false
			}
		}
		if deferredOnly {
			return "defer", "post-port cut: mixed deferred architecture"
		}
		return "extract", "split by path between port stage and post-port cut"
	}
	return "review", "Stage 0: category review"
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func gitOutput(dir string, args ...string) (string, error) {
	return commandOutput(dir, "git", args...)
}

func commandOutput(dir, name string, args ...string) (string, error) {
	attempts := 1
	if name == "gh" {
		attempts = 3
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		cmd := exec.Command(name, args...)
		cmd.Dir = dir
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		output, err := cmd.Output()
		if err == nil {
			return strings.TrimSpace(string(output)), nil
		}
		lastErr = fmt.Errorf("%s %v: %w: %s", name, args, err,
			strings.TrimSpace(stderr.String()))
		if attempt < attempts {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return "", lastErr
}

func check(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, flag.ErrHelp) {
		os.Exit(0)
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
