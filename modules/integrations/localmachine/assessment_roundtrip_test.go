package localmachine

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

func TestAssessmentEvidenceRoundTrip(t *testing.T) {
	now := time.Now().UTC()
	want := Assessment{Version: AssessmentVersion, Captured: now, Categories: map[string]AssessmentCapture{
		"policy-provenance": {Started: now, Completed: now.Add(time.Second), Scope: "cached-policy", Truncated: true,
			Result: basedata.CollectionResult{Status: basedata.CollectionAccessDenied}, Records: []json.RawMessage{json.RawMessage(`{"GPOID":"synthetic-policy","Scope":"machine"}`)}},
	}}
	want.Paths = []PathSecurity{{Path: `C:\Windows\Sysnative\fixture.exe`, ConfiguredPath: `%SystemRoot%\System32\fixture.exe`, InspectionPath: `C:\Windows\Sysnative\fixture.exe`, FinalPath: `\\?\C:\Windows\System32\fixture.exe`, FileID: "0000000000000001", VolumeSerial: "12345678", Result: basedata.CollectionResult{Status: basedata.CollectionCollected}, IdentityResult: basedata.CollectionResult{Status: basedata.CollectionCollected}}}
	raw, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	info := Info{AssessmentData: string(raw)}
	check := func(t *testing.T, got Info) {
		t.Helper()
		decoded, err := DecodeAssessment(got.AssessmentData)
		if err != nil || !reflect.DeepEqual(decoded, want) {
			t.Fatalf("evidence changed: %+v, %v", decoded, err)
		}
	}
	t.Run("container", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "synthetic.lmc")
		if err := WriteCollection(path, info, nil); err != nil {
			t.Fatal(err)
		}
		got, _, err := ReadCollection(path)
		if err != nil {
			t.Fatal(err)
		}
		check(t, got)
	})
	t.Run("legacy-message", func(t *testing.T) {
		raw, err := info.MarshalMsg(nil)
		if err != nil {
			t.Fatal(err)
		}
		var got Info
		if _, err := got.UnmarshalMsg(raw); err != nil {
			t.Fatal(err)
		}
		check(t, got)
	})
	t.Run("json", func(t *testing.T) {
		raw, err := json.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		var got Info
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		check(t, got)
	})
}
