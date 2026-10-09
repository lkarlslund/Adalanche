package collect

import (
	"runtime"
	"runtime/debug"
	"time"

	"github.com/lkarlslund/adalanche/modules/basedata"
	"github.com/lkarlslund/adalanche/modules/ui"
)

// collectWorkers is the number of collection jobs run at once; 0 selects
// defaultCollectWorkers.
var collectWorkers int

// Default to a quarter of the logical processors so collection stays in the
// background on busy servers. Small machines run jobs one at a time.
func defaultCollectWorkers() int {
	return max(1, runtime.NumCPU()/4)
}

func effectiveCollectWorkers() int {
	if collectWorkers > 0 {
		return collectWorkers
	}
	return defaultCollectWorkers()
}

// collectJob gathers one independent part of the collection. run writes only
// to its own locals and to the outcomes map it is given, and returns a merge
// function (or nil) that publishes its result. Merges run on the caller's
// goroutine, in job order, after every job has finished or been abandoned.
type collectJob struct {
	name    string
	timeout time.Duration
	run     func(outcomes basedata.CollectionResults) (merge func())
}

// Every job's own result is recorded under this outcome prefix.
const collectJobOutcomePrefix = "collection/"

type collectJobResult struct {
	outcomes basedata.CollectionResults
	merge    func()
	result   basedata.CollectionResult
}

// runCollectJobs runs jobs on at most workers goroutines. A panic fails only
// the job that raised it; outcomes it recorded before the panic are kept, but
// its merge never runs. A job still running at its timeout is abandoned: its
// worker slot is released, nothing it produces is read, and it is recorded as
// timed out. Native calls cannot be interrupted, so an abandoned job may keep
// running until the process exits.
func runCollectJobs(jobs []collectJob, workers int, outcomes basedata.CollectionResults) {
	workers = max(1, workers)
	results := make([]collectJobResult, len(jobs))
	slots := make(chan struct{}, workers)
	finished := make(chan int, len(jobs))
	for index := range jobs {
		go func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			results[index] = runCollectJob(jobs[index])
			finished <- index
		}()
	}
	for range jobs {
		<-finished
	}
	for index, job := range jobs {
		r := results[index]
		for key, value := range r.outcomes {
			outcomes[key] = value
		}
		outcomes[collectJobOutcomePrefix+job.name] = r.result
		if r.merge != nil {
			r.merge()
		}
	}
}

func runCollectJob(job collectJob) collectJobResult {
	done := make(chan collectJobResult, 1) // An abandoned job must never block on send.
	started := time.Now()
	go func() {
		r := collectJobResult{outcomes: basedata.CollectionResults{}, result: basedata.CollectionResultFromError(nil)}
		defer func() {
			if p := recover(); p != nil {
				r.merge = nil
				r.result = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "panic"}
				ui.Error().Msgf("Collection of %v failed unexpectedly and was skipped: %v\n%s", job.name, p, debug.Stack())
			}
			done <- r
		}()
		r.merge = job.run(r.outcomes)
	}()
	var timeout <-chan time.Time
	if job.timeout > 0 {
		timer := time.NewTimer(job.timeout)
		defer timer.Stop()
		timeout = timer.C
	}
	select {
	case r := <-done:
		ui.Debug().Msgf("Collection of %v finished in %v", job.name, time.Since(started).Round(time.Millisecond))
		return r
	case <-timeout:
		ui.Warn().Msgf("Collection of %v did not finish within %v and was abandoned", job.name, job.timeout)
		return collectJobResult{result: basedata.CollectionResult{Status: basedata.CollectionTimedOut, ErrorCode: "job_deadline"}}
	}
}
