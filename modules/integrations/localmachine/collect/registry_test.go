package collect

import (
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

func TestRunCollectorsStagesAndMerges(t *testing.T) {
	oldOnly, oldSkip := assessmentOnly, assessmentSkip
	t.Cleanup(func() { assessmentOnly, assessmentSkip = oldOnly, oldSkip })
	assessmentOnly, assessmentSkip = nil, []string{"skipped-category"}

	release := make(chan struct{})
	defer close(release)
	skippedRan := false
	collectors := []Collector{
		// Registered out of stage order on purpose.
		{Name: "inventory", Stage: StageInventory, Collect: func(env *Env) func(*Result) {
			if env.Info.Machine.Name != "host" {
				t.Error("inventory ran before identity was merged")
			}
			env.Outcomes["inventory/read"] = basedata.CollectionResultFromError(nil)
			return func(r *Result) { r.Info.Users = lm.Users{{Name: "user"}} }
		}},
		{Name: "identity", Stage: StageIdentity, Collect: func(env *Env) func(*Result) {
			return func(r *Result) { r.Info.Machine.Name = "host" }
		}},
		{Name: "category", Category: "test-category", Stage: StageAssessment, Collect: func(env *Env) func(*Result) {
			if len(env.Info.Users) != 1 {
				t.Error("assessment ran before inventory was merged")
			}
			return func(r *Result) {
				r.Assessment.Categories["test-category"] = lm.AssessmentCapture{Result: basedata.CollectionResultFromError(nil)}
				r.Extensions["category"] = 42
			}
		}},
		{Name: "skipped", Category: "skipped-category", Stage: StageAssessment, Collect: func(*Env) func(*Result) {
			skippedRan = true
			return nil
		}},
		{Name: "stuck", Category: "stuck-category", Stage: StageAssessment, Timeout: 20 * time.Millisecond, Collect: func(*Env) func(*Result) {
			<-release
			return nil
		}},
		{Name: "derived", Stage: StageDerived, Collect: func(env *Env) func(*Result) {
			if _, ok := env.Assessment.Categories["test-category"]; !ok {
				t.Error("derived stage ran before assessment was merged")
			}
			return nil
		}},
	}

	r := runCollectors(collectors, 2)
	if skippedRan {
		t.Fatal("deselected category collector ran")
	}
	if r.Info.Machine.Name != "host" || len(r.Info.Users) != 1 || r.Extensions["category"] != 42 {
		t.Fatalf("merges missing: %+v", r)
	}
	a, err := lm.DecodeAssessment(r.Info.AssessmentData)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]basedata.CollectionStatus{
		"test-category":    basedata.CollectionCollected,
		"skipped-category": basedata.CollectionNotRequested,
		"stuck-category":   basedata.CollectionTimedOut,
	} {
		if got := a.Categories[name].Result.Status; got != want {
			t.Errorf("category %s: %v, want %v", name, got, want)
		}
		if got := r.Info.CollectionResults["assessment/"+name].Status; got != want {
			t.Errorf("outcome for %s: %v, want %v", name, got, want)
		}
	}
	if r.Info.CollectionResults["inventory/read"].Status != basedata.CollectionCollected {
		t.Fatal("collector outcomes were not merged")
	}
	if r.Info.Collected.IsZero() {
		t.Fatal("collection time missing")
	}
}

func TestRegisterCollectorRejectsDuplicates(t *testing.T) {
	old := registeredCollectors
	t.Cleanup(func() { registeredCollectors = old })
	registeredCollectors = nil
	noop := func(*Env) func(*Result) { return nil }
	RegisterCollector(Collector{Name: "a", Category: "x", Collect: noop})
	for _, c := range []Collector{
		{Name: "a", Collect: noop},
		{Name: "b", Category: "x", Collect: noop},
		{Name: "c"},
		{Collect: noop},
		{Name: "d", Stage: stageCount, Collect: noop},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("accepted %+v", c)
				}
			}()
			RegisterCollector(c)
		}()
	}
}
