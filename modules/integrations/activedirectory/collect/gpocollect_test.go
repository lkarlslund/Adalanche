package collect

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/lkarlslund/adalanche/modules/integrations/activedirectory"
)

func policyJobs(t *testing.T, count int) []policyJob {
	t.Helper()
	output := t.TempDir()
	jobs := make([]policyJob, count)
	for i := range jobs {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "GPT.INI"), fmt.Appendf(nil, "[General]\nVersion=%d\n", i), 0600); err != nil {
			t.Fatal(err)
		}
		jobs[i] = policyJob{
			info:   activedirectory.GPOdump{GPOinfo: activedirectory.GPOinfo{Path: root}},
			local:  root,
			output: filepath.Join(output, fmt.Sprintf("policy%d.gpc", i)),
		}
	}
	return jobs
}

func TestPolicyCollectorParallel(t *testing.T) {
	jobs := policyJobs(t, 25)
	for i, err := range (policyCollector{workers: 4}).run(context.Background(), jobs) {
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		info, err := activedirectory.ReadGPOCollection(jobs[i].output)
		if err != nil {
			t.Fatalf("job %d: %v", i, err)
		}
		want := fmt.Sprintf("[General]\nVersion=%d\n", i)
		if len(info.Files) != 2 || string(info.Files[1].Contents) != want {
			t.Fatalf("job %d collected %+v", i, info.Files)
		}
	}
}

func TestPolicyCollectorStopsAfterFailure(t *testing.T) {
	jobs := policyJobs(t, 25)
	jobs[3].output = filepath.Join(t.TempDir(), "missing", "policy.gpc")
	var failures int
	for i, err := range (policyCollector{workers: 4}).run(context.Background(), jobs) {
		switch {
		case err == nil, errors.Is(err, errPolicyAborted):
		case i == 3:
			failures++
		default:
			t.Fatalf("job %d: unexpected error %v", i, err)
		}
	}
	if failures != 1 {
		t.Fatalf("expected the failing job to report its own error, got %d", failures)
	}
}
