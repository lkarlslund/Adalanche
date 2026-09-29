package collect

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A source guard, not a proof about every dependency. Scan all platform files
// even on non-Windows CI. Collection must never launch a process/script engine.
func TestCollectorsUseNativeAPIsOnly(t *testing.T) {
	for _, root := range []string{".", "../../activedirectory/collect", "../../../windowssecurity", "../../../cli/collect"} {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(path)) {
			case ".ps1", ".bat", ".cmd", ".vbs", ".hta":
				t.Errorf("collector script asset: %s", path)
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, imp := range file.Imports {
				if imp.Path.Value == `"os/exec"` {
					t.Errorf("process launcher import: %s", path)
				}
			}
			ast.Inspect(file, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.SelectorExpr:
					if prohibitedNativeSymbol(n.Sel.Name) {
						t.Errorf("process launcher at %s", fset.Position(n.Pos()))
					}
				case *ast.CallExpr:
					if method, ok := n.Fun.(*ast.SelectorExpr); ok && method.Sel.Name == "Run" {
						t.Errorf("execution method at %s", fset.Position(n.Pos()))
					}
				case *ast.BasicLit:
					if n.Kind != token.STRING {
						break
					}
					value, err := strconv.Unquote(n.Value)
					if err != nil {
						break
					}
					if prohibitedNativeSymbol(value) {
						t.Errorf("process launcher symbol at %s", fset.Position(n.Pos()))
					}
					if value == "Run" || value == "Exec" || value == "CreateShell" {
						t.Errorf("execution method at %s", fset.Position(n.Pos()))
					}
					switch strings.ToLower(value) {
					case "wscript.shell", "shell.application", "msscriptcontrol.scriptcontrol", "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe":
						t.Errorf("script host at %s", fset.Position(n.Pos()))
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func prohibitedNativeSymbol(name string) bool {
	for _, prefix := range []string{"StartProcess", "CreateProcess", "ShellExecute", "WinExec", "NtCreateUserProcess", "RtlCreateUserProcess"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
