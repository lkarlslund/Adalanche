package localmachine

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

func TestAssessmentRoundTrip(t *testing.T) {
	a := Assessment{Version: AssessmentVersion, Captured: time.Now().UTC(), Categories: map[string]AssessmentCapture{"smb-server": {Result: basedata.CollectionResult{Status: basedata.CollectionAccessDenied}}}}
	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	i := Info{AssessmentData: string(raw)}
	encoded, err := i.MarshalMsg(nil)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Info
	if rest, err := decoded.UnmarshalMsg(encoded); err != nil || len(rest) != 0 {
		t.Fatalf("decode: %v", err)
	}
	got, err := DecodeAssessment(decoded.AssessmentData)
	if err != nil || got.Categories["smb-server"].Result.Status != basedata.CollectionAccessDenied {
		t.Fatalf("lost outcome: %+v %v", got, err)
	}
	for _, invalid := range []string{"", "{}", `{"version":999,"captured":"2026-01-01T00:00:00Z","categories":{}}`, string(raw) + "{}"} {
		if _, err := DecodeAssessment(invalid); err == nil {
			t.Error("accepted invalid assessment")
		}
	}
}
