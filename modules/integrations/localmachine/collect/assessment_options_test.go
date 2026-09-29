package collect

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func TestAssessmentSelection(t *testing.T) {
	oldOnly, oldSkip := assessmentOnly, assessmentSkip
	t.Cleanup(func() { assessmentOnly, assessmentSkip = oldOnly, oldSkip })
	known := []string{"current-sessions", "path-security", "extension"}
	for _, tt := range []struct {
		only, skip []string
		valid      bool
	}{
		{nil, nil, true}, {[]string{"current-sessions"}, nil, true}, {nil, []string{"extension"}, true},
		{[]string{"unknown"}, nil, false}, {nil, []string{"typo"}, false}, {[]string{"extension"}, []string{"extension"}, false},
	} {
		if err := validateAssessmentSelection(tt.only, tt.skip, known); (err == nil) != tt.valid {
			t.Fatalf("selection %v/%v: %v", tt.only, tt.skip, err)
		}
	}
	assessmentOnly, assessmentSkip = nil, []string{"current-sessions"}
	if AssessmentEnabled("current-sessions") || !AssessmentEnabled("path-security") {
		t.Fatal("skip selection ignored")
	}
	assessmentOnly, assessmentSkip = []string{"extension"}, nil
	if AssessmentEnabled("path-security") || !AssessmentEnabled("extension") {
		t.Fatal("only selection ignored")
	}
	assessmentOnly = nil
	if !AssessmentEnabled("path-security") {
		t.Fatal("default should collect all")
	}
}

func TestAssessmentSummary(t *testing.T) {
	stamp := time.Now().UTC()
	a := lm.Assessment{Version: lm.AssessmentVersion, Captured: stamp, Categories: map[string]lm.AssessmentCapture{
		"current-sessions": {Started: stamp, Completed: stamp.Add(time.Second), Result: basedata.CollectionResult{Status: basedata.CollectionAccessDenied, ErrorCode: "hresult:80070005"}, Truncated: true, Records: []json.RawMessage{json.RawMessage(`{"User":"private-identity"}`)}},
		"path-security":    {Result: basedata.CollectionResult{Status: basedata.CollectionNotRequested}},
	}}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	WriteAssessmentSummary(&output, &lm.Info{AssessmentData: string(raw)})
	s := output.String()
	for _, want := range []string{"denied=1", "skipped=1", "truncated=1", "current-sessions", "1s", "hresult:80070005"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in %q", want, s)
		}
	}
	if strings.Contains(s, "private-identity") || strings.Contains(s, "path-security") {
		t.Fatal("summary leaked identity or expanded skipped category")
	}
}
