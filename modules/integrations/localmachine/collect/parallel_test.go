package collect

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

func TestCollectJobsIsolatePanics(t *testing.T) {
	var merged []string
	outcomes := basedata.CollectionResults{}
	runCollectJobs([]collectJob{
		{name: "first", run: func(o basedata.CollectionResults) func() {
			o["first/read"] = basedata.CollectionResultFromError(nil)
			return func() { merged = append(merged, "first") }
		}},
		{name: "broken", run: func(o basedata.CollectionResults) func() {
			o["broken/before"] = basedata.CollectionResultFromError(nil)
			if len(o) > 0 {
				panic("unexpected provider state")
			}
			return func() { merged = append(merged, "broken") }
		}},
		{name: "last", run: func(o basedata.CollectionResults) func() {
			return func() { merged = append(merged, "last") }
		}},
	}, 2, outcomes)

	if len(merged) != 2 || merged[0] != "first" || merged[1] != "last" {
		t.Fatalf("merged %v, want first and last in job order", merged)
	}
	if got := outcomes["collection/broken"]; got.Status != basedata.CollectionFailed || got.ErrorCode != "panic" {
		t.Fatalf("panicking job recorded %+v", got)
	}
	if _, ok := outcomes["broken/before"]; !ok {
		t.Fatal("outcomes recorded before the panic were lost")
	}
	for _, name := range []string{"first", "last"} {
		if got := outcomes["collection/"+name]; got.Status != basedata.CollectionCollected {
			t.Fatalf("job %v recorded %+v", name, got)
		}
	}
}

func TestCollectJobsAbandonAfterTimeout(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	merged := false
	outcomes := basedata.CollectionResults{}
	start := time.Now()
	runCollectJobs([]collectJob{
		{name: "stuck", timeout: 20 * time.Millisecond, run: func(o basedata.CollectionResults) func() {
			<-release
			o["stuck/late"] = basedata.CollectionResultFromError(nil)
			return func() { merged = true }
		}},
		{name: "after", run: func(basedata.CollectionResults) func() { return nil }},
	}, 1, outcomes)

	if time.Since(start) > 5*time.Second {
		t.Fatal("stuck job blocked the run")
	}
	if merged {
		t.Fatal("abandoned job was merged")
	}
	if got := outcomes["collection/stuck"]; got.Status != basedata.CollectionTimedOut {
		t.Fatalf("stuck job recorded %+v", got)
	}
	if _, ok := outcomes["stuck/late"]; ok {
		t.Fatal("abandoned job's outcomes were read")
	}
	if got := outcomes["collection/after"]; got.Status != basedata.CollectionCollected {
		t.Fatalf("job queued behind the stuck one recorded %+v", got)
	}
}

func TestCollectJobsRespectWorkerLimit(t *testing.T) {
	var running, peak atomic.Int32
	jobs := make([]collectJob, 12)
	for i := range jobs {
		jobs[i] = collectJob{name: string(rune('a' + i)), run: func(basedata.CollectionResults) func() {
			now := running.Add(1)
			for {
				old := peak.Load()
				if now <= old || peak.CompareAndSwap(old, now) {
					break
				}
			}
			time.Sleep(5 * time.Millisecond)
			running.Add(-1)
			return nil
		}}
	}
	runCollectJobs(jobs, 3, basedata.CollectionResults{})
	if got := peak.Load(); got > 3 || got < 1 {
		t.Fatalf("peak concurrency %d, want 1..3", got)
	}
}

func TestDefaultCollectWorkers(t *testing.T) {
	if defaultCollectWorkers() < 1 {
		t.Fatal("default must allow at least one worker")
	}
	collectWorkers = 7
	defer func() { collectWorkers = 0 }()
	if effectiveCollectWorkers() != 7 {
		t.Fatal("explicit worker count ignored")
	}
}
