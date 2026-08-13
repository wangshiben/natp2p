package terminationpolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestReusableFrameworkHasNoProcessTerminationCalls(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve policy test location")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(repositoryRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			relative, err := filepath.Rel(repositoryRoot, path)
			if err != nil {
				return err
			}
			first := strings.Split(filepath.ToSlash(relative), "/")[0]
			switch first {
			case ".git", "ca_web", "cmd", "scripts", "test", "test-evidence", "pacakgeTest", "speed_test":
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		parsed, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || !terminatesProcess(call.Fun) {
				return true
			}
			position := fileSet.Position(call.Pos())
			relative, _ := filepath.Rel(repositoryRoot, position.Filename)
			t.Errorf("runtime process termination is forbidden in reusable framework code: %s:%d", relative, position.Line)
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestReviewedCommandTerminationCallsDoNotChange(t *testing.T) {
	reviewed := map[string]int{
		"test/testCode/billing-adversary-node/main.go#main":  2,
		"test/testCode/billing-adversary-probe/main.go#main": 4,
		"test/testCode/billing-toctou-demo/main.go#main":     2,
		"test/testCode/billing-toctou-demo/main.go#must":     1,
		"test/testCode/billingpoc-race/main.go#main":         4,
		"test/testCode/billingpoc-race/main.go#must":         1,
		"test/testCode/billingpoc/main.go#main":              3,
		"test/testCode/billingpoc/main.go#must":              1,
		"test/testCode/billingqueue-inspect/main.go#main":    1,
		"test/testCode/client_a/main.go#main":                3,
		"test/testCode/client_b/main.go#main":                5,
		"test/testCode/hooktest/main.go#main":                1,
		"test/testCode/hooktest/main.go#runConnect":          5,
		"test/testCode/hooktest/main.go#runListen":           2,
		"test/testCode/hooktest/main.go#runRelay":            2,
		"test/testCode/relay_server/main.go#main":            1,
		"test/testCode/relaychat/main.go#main":               1,
		"test/testCode/relaychat/main.go#runConnect":         7,
		"test/testCode/relaychat/main.go#runListen":          4,
		"test/testCode/relaychat/main.go#runRelay":           4,
		"cmd/tunnel/client/main.go#main":                     6,
		"test/testCode/tunnel/httpfileserver/main.go#main":   2,
		"test/testCode/tunnel/nodeserver/main.go#main":       4,
		"cmd/tunnel/server/main.go#main":                     8,
		"test/testCode/tunnel/test_validator/main.go#main":   2,
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve policy test location")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	fileSet := token.NewFileSet()
	actual := make(map[string]int)
	commandRoots := []string{filepath.Join(repositoryRoot, "cmd"), filepath.Join(repositoryRoot, "test", "testCode")}
	for _, commandRoot := range commandRoots {
		err := filepath.WalkDir(commandRoot, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(fileSet, path, nil, 0)
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(repositoryRoot, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			for _, declaration := range parsed.Decls {
				function, ok := declaration.(*ast.FuncDecl)
				if !ok || function.Body == nil {
					continue
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					call, ok := node.(*ast.CallExpr)
					if !ok {
						return true
					}
					kind := terminationKind(call.Fun)
					if kind == "" {
						return true
					}
					position := fileSet.Position(call.Pos())
					if kind != "exit" && kind != "fatal" {
						t.Errorf("%s is never approved in command code: %s:%d function=%s", kind, relative, position.Line, function.Name.Name)
						return true
					}
					key := relative + "#" + function.Name.Name
					if _, ok := reviewed[key]; !ok {
						t.Errorf("unreviewed command termination: %s:%d function=%s kind=%s", relative, position.Line, function.Name.Name, kind)
						return true
					}
					actual[key]++
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for key, expected := range reviewed {
		if actual[key] != expected {
			t.Errorf("reviewed command termination count changed for %s: got %d want %d", key, actual[key], expected)
		}
	}
}

func terminatesProcess(expression ast.Expr) bool {
	return terminationKind(expression) != ""
}

func terminationKind(expression ast.Expr) string {
	if identifier, ok := expression.(*ast.Ident); ok {
		if identifier.Name == "panic" {
			return "panic"
		}
		return ""
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	packageName, ok := selector.X.(*ast.Ident)
	if !ok {
		return ""
	}
	switch packageName.Name {
	case "os":
		if selector.Sel.Name == "Exit" {
			return "exit"
		}
	case "runtime":
		if selector.Sel.Name == "Goexit" {
			return "goexit"
		}
	case "syscall", "unix":
		if selector.Sel.Name == "Kill" {
			return "kill"
		}
	case "log":
		if strings.HasPrefix(selector.Sel.Name, "Fatal") {
			return "fatal"
		}
		if strings.HasPrefix(selector.Sel.Name, "Panic") {
			return "panic"
		}
	}
	return ""
}
