package collect

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

//go:embed assessment.ps1
var assessmentTestScript string

func TestAssessmentScriptSyntaxAndOutcomes(t *testing.T) {
	ps, err := exec.LookPath("pwsh")
	if err != nil {
		t.Skip("PowerShell is not installed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", `$tokens=$null; $errors=$null; [System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$tokens, [ref]$errors) | Out-Null; if ($errors.Count -ne 0) { $errors | Out-String | Write-Output; exit 1 }`)
	check.Stdin = strings.NewReader(assessmentTestScript)
	if out, err := check.CombinedOutput(); err != nil {
		t.Fatalf("script syntax: %v: %s", err, out)
	}
	prefix, _, ok := strings.Cut(assessmentTestScript, "Capture 'smb-client'")
	if !ok {
		t.Fatal("missing capture entry point")
	}
	// Exercise the actual capture helper, without executing host queries.
	command := exec.CommandContext(ctx, ps, "-NoProfile", "-NonInteractive", "-Command", prefix+`
Capture 'empty' {}
Capture 'denied' { throw [System.UnauthorizedAccessException]::new('synthetic') }
Capture 'failed' { [pscustomobject]@{Value=1}; throw 'synthetic' }
Capture 'limit' { 1..10001 }
`)
	out, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		status  string
		records int
	}{"empty": {"collected", 0}, "denied": {"access_denied", 0}, "failed": {"failed", 1}, "limit": {"failed", 10000}}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var line struct {
			Name    string
			Capture lm.AssessmentCapture
		}
		if err := json.Unmarshal(scanner.Bytes(), &line); err != nil {
			t.Fatal(err)
		}
		expected, ok := want[line.Name]
		if !ok || string(line.Capture.Result.Status) != expected.status || len(line.Capture.Records) != expected.records {
			t.Fatalf("incorrect outcome for %s: %+v", line.Name, line.Capture.Result)
		}
		delete(want, line.Name)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	if len(want) != 0 {
		t.Fatalf("missing outcomes: %v", want)
	}
}
