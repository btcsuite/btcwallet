//go:build ignore

// sql-port-api-baseline records the current wallet.Interface and the wallet
// package surface referenced by lnd.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/tools/go/packages"
)

const walletImport = "github.com/btcsuite/btcwallet/wallet"
const btcwalletModule = "github.com/btcsuite/btcwallet"

type reference struct {
	production map[string]struct{}
	test       map[string]struct{}
}

func newReference() *reference {
	return &reference{
		production: make(map[string]struct{}),
		test:       make(map[string]struct{}),
	}
}

func main() {
	var (
		btcwalletDir = flag.String("btcwallet", "", "path to btcwallet")
		lndDir       = flag.String("lnd", "", "path to an lnd checkout")
		out          = flag.String("out", "", "output Markdown path")
	)
	flag.Parse()

	if *btcwalletDir == "" || *lndDir == "" || *out == "" {
		fmt.Fprintln(os.Stderr, "-btcwallet, -lnd, and -out are required")
		os.Exit(2)
	}

	btcwalletSHA, err := gitOutput(*btcwalletDir, "rev-parse", "HEAD")
	check(err)
	lndSHA, err := gitOutput(*lndDir, "rev-parse", "HEAD")
	check(err)
	lndWalletVersion, err := moduleVersion(
		filepath.Join(*lndDir, "go.mod"), btcwalletModule,
	)
	check(err)

	methods, err := interfaceMethods(filepath.Join(
		*btcwalletDir, "wallet", "interface.go",
	))
	check(err)
	methodRefs, concreteRefs, packageRefs, err := lndReferences(*lndDir)
	check(err)

	var doc bytes.Buffer
	fmt.Fprintln(&doc, "# SQL Port API Baseline")
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "In this snapshot, we record the public wallet contract that the port-first branch must preserve. The lnd side is pinned to an exact checkout, so later API checks can distinguish a btcwallet regression from unrelated lnd movement.")
	fmt.Fprintln(&doc)
	fmt.Fprintf(&doc, "- btcwallet baseline: `%s`\n", btcwalletSHA)
	fmt.Fprintf(&doc, "- lnd audit checkout: `%s`\n", lndSHA)
	fmt.Fprintf(&doc, "- lnd btcwallet module requirement: `%s`\n", lndWalletVersion)
	fmt.Fprintln(&doc, "- generator: `./scripts/sql-port-api-baseline.sh <lnd-checkout> [btcwallet-ref] [lnd-ref]`")
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "## `wallet.Interface`")
	fmt.Fprintln(&doc)
	fmt.Fprintf(&doc, "The interface contains %d methods. Signatures are copied from `wallet/interface.go`, not reconstructed from documentation.\n", len(methods))
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "| Method | Signature | Non-test lnd references |")
	fmt.Fprintln(&doc, "| --- | --- | --- |")
	for _, method := range methods {
		refs := methodRefs[method.name]
		fmt.Fprintf(
			&doc, "| `%s` | `%s` | %s |\n", method.name,
			escapeTable(method.signature), formatLocations(refs, true),
		)
	}

	usedMethods := make([]string, 0, len(methodRefs))
	for method := range methodRefs {
		usedMethods = append(usedMethods, method)
	}
	sort.Strings(usedMethods)
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "## Direct interface call set")
	fmt.Fprintln(&doc)
	fmt.Fprintf(&doc, "The lnd checkout directly calls %d methods through a `wallet.Interface`. These calls are the narrowest source-compatibility gate for the SQL port.\n", len(usedMethods))
	fmt.Fprintln(&doc)
	for _, method := range usedMethods {
		fmt.Fprintf(&doc, "- `%s`: %s\n", method, formatLocations(methodRefs[method], true))
	}

	packageSymbols := make([]string, 0, len(packageRefs))
	for symbol := range packageRefs {
		packageSymbols = append(packageSymbols, symbol)
	}
	sort.Strings(packageSymbols)
	fmt.Fprintln(&doc)
	concreteMethods := make([]string, 0, len(concreteRefs))
	for method := range concreteRefs {
		concreteMethods = append(concreteMethods, method)
	}
	sort.Strings(concreteMethods)
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "## Concrete wallet package methods referenced by lnd")
	fmt.Fprintln(&doc)
	fmt.Fprintf(&doc, "Outside `wallet.Interface`, lnd calls %d exported methods on concrete types from the wallet package. These are compatibility constraints too, in particular the loader and the concrete `Wallet` passed through lnd's unlock path.\n", len(concreteMethods))
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "| Method | Non-test Go references | `_test.go` references |")
	fmt.Fprintln(&doc, "| --- | --- | --- |")
	for _, method := range concreteMethods {
		refs := concreteRefs[method]
		fmt.Fprintf(
			&doc, "| `%s` | %s | %s |\n", method,
			formatReferenceSet(refs.production),
			formatReferenceSet(refs.test),
		)
	}

	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "## Wallet package-level identifiers referenced by lnd")
	fmt.Fprintln(&doc)
	fmt.Fprintf(&doc, "Across the lnd checkout, Go files reference %d exported package-level identifiers from `%s`. The non-test and `_test.go` columns are kept separate because both matter, but only non-test references constrain an lnd binary build.\n", len(packageSymbols), walletImport)
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "| Symbol | Non-test Go references | `_test.go` references |")
	fmt.Fprintln(&doc, "| --- | --- | --- |")
	for _, symbol := range packageSymbols {
		refs := packageRefs[symbol]
		fmt.Fprintf(
			&doc, "| `%s` | %s | %s |\n", symbol,
			formatReferenceSet(refs.production),
			formatReferenceSet(refs.test),
		)
	}

	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "## Audit boundary")
	fmt.Fprintln(&doc)
	fmt.Fprintln(&doc, "The lnd scan uses Go type information, then separates `_test.go` references from other Go files. It does not claim to find reflection, generated code outside the checkout, or downstream users other than lnd. The port gate should still compile unmodified lnd against each candidate btcwallet tip.")

	check(os.MkdirAll(filepath.Dir(*out), 0o755))
	check(os.WriteFile(*out, doc.Bytes(), 0o644))
}

type method struct {
	name      string
	signature string
}

func interfaceMethods(path string) ([]method, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}

	var methods []method
	for _, decl := range file.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gen.Specs {
			typeSpec, ok := spec.(*ast.TypeSpec)
			if !ok || typeSpec.Name.Name != "Interface" {
				continue
			}
			iface, ok := typeSpec.Type.(*ast.InterfaceType)
			if !ok {
				return nil, fmt.Errorf("wallet.Interface is not an interface")
			}
			for _, field := range iface.Methods.List {
				if len(field.Names) != 1 {
					return nil, fmt.Errorf("unexpected embedded interface field")
				}
				var signature bytes.Buffer
				if err := format.Node(&signature, fset, field.Type); err != nil {
					return nil, err
				}
				methodType := strings.TrimPrefix(
					collapseSpace(signature.String()), "func",
				)
				methods = append(methods, method{
					name:      field.Names[0].Name,
					signature: field.Names[0].Name + methodType,
				})
			}
		}
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("wallet.Interface not found in %s", path)
	}
	return methods, nil
}

func lndReferences(lndDir string) (map[string]*reference,
	map[string]*reference, map[string]*reference, error) {

	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles |
			packages.NeedCompiledGoFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
		Dir:   lndDir,
		Tests: true,
	}
	pkgs, err := packages.Load(cfg, "./...")
	if err != nil {
		return nil, nil, nil, err
	}
	if packages.PrintErrors(pkgs) != 0 {
		return nil, nil, nil, fmt.Errorf("lnd package load failed")
	}

	interfaceRefs := make(map[string]*reference)
	concreteRefs := make(map[string]*reference)
	packageRefs := make(map[string]*reference)
	for _, pkg := range pkgs {
		for _, file := range pkg.Syntax {
			ast.Inspect(file, func(node ast.Node) bool {
				sel, ok := node.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				location := relativeLocation(
					lndDir, pkg.Fset.Position(sel.Pos()),
				)
				isTest := strings.Contains(location, "_test.go:")

				selection := pkg.TypesInfo.Selections[sel]
				if selection == nil {
					obj := pkg.TypesInfo.Uses[sel.Sel]
					if objectFromWallet(obj) {
						addReference(
							packageRefs, obj.Name(), location,
							isTest,
						)
					}
					return true
				}

				method, ok := selection.Obj().(*types.Func)
				if !ok || !objectFromWallet(method) ||
					!method.Exported() {

					return true
				}
				receiver := receiverName(selection.Recv())
				switch receiver {
				case "Interface":
					addReference(
						interfaceRefs, method.Name(), location,
						isTest,
					)
				case "":
					return true
				default:
					addReference(
						concreteRefs, receiver+"."+method.Name(),
						location, isTest,
					)
				}
				return true
			})
		}
	}

	return interfaceRefs, concreteRefs, packageRefs, nil
}

func objectFromWallet(obj types.Object) bool {
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == walletImport
}

func receiverName(receiver types.Type) string {
	if pointer, ok := receiver.(*types.Pointer); ok {
		receiver = pointer.Elem()
	}
	named, ok := receiver.(*types.Named)
	if !ok || named.Obj().Pkg() == nil ||
		named.Obj().Pkg().Path() != walletImport {

		return ""
	}
	return named.Obj().Name()
}

func addReference(refs map[string]*reference, name, location string,
	isTest bool) {

	ref := refs[name]
	if ref == nil {
		ref = newReference()
		refs[name] = ref
	}
	if isTest {
		ref.test[location] = struct{}{}
	} else {
		ref.production[location] = struct{}{}
	}
}

func gitOutput(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

func moduleVersion(path, module string) (string, error) {
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(contents), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == module {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("module %s not found in %s", module, path)
}

func relativeLocation(root string, pos token.Position) string {
	path, err := filepath.Rel(root, pos.Filename)
	if err != nil {
		path = pos.Filename
	}
	return fmt.Sprintf("%s:%d", filepath.ToSlash(path), pos.Line)
}

func formatLocations(ref *reference, code bool) string {
	if ref == nil {
		return "none"
	}
	return formatReferenceSetWithCode(ref.production, code)
}

func formatReferenceSet(refs map[string]struct{}) string {
	return formatReferenceSetWithCode(refs, true)
}

func formatReferenceSetWithCode(refs map[string]struct{}, code bool) string {
	if len(refs) == 0 {
		return "none"
	}
	locations := make([]string, 0, len(refs))
	for location := range refs {
		if code {
			locations = append(locations, "`"+location+"`")
		} else {
			locations = append(locations, location)
		}
	}
	sort.Strings(locations)
	return strings.Join(locations, "<br>")
}

func collapseSpace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func escapeTable(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func check(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
