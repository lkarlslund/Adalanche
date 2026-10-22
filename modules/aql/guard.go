package aql

import (
	"context"
	"errors"
	"fmt"
	"math"
	"runtime/debug"
	"runtime/metrics"
	"time"

	"github.com/lkarlslund/adalanche/modules/ui"
)

// Searches share the process with the graph, so one broad search, or a few
// at once, can use up the memory and get the whole server killed, taking
// every client with it. So searches run one at a time, and a watchdog stops
// the one running when the process goes over its memory limit, or the
// system as a whole is about to run out of memory, before the system's out
// of memory killer stops everything.

// ErrSearchMemory is why a search was stopped for want of memory.
var ErrSearchMemory = errors.New("the search was stopped because the server is running out of memory; narrow the query, or lower its depth or node limit")

// searchSlot is held by the search running; others wait for it.
var searchSlot = make(chan struct{}, 1)

// memoryWatchInterval is how often a running search's memory is checked.
const memoryWatchInterval = 100 * time.Millisecond

// memoryShort returns why memory is running out, or "" while it is not.
// Tests replace it.
var memoryShort = memoryShortNow

func memoryShortNow() string {
	samples := []metrics.Sample{
		{Name: "/memory/classes/total:bytes"},
		{Name: "/memory/classes/heap/released:bytes"},
	}
	metrics.Read(samples)
	used := samples[0].Value.Uint64() - samples[1].Value.Uint64()
	// The Go memory limit is soft: the collector works harder near it, and
	// the process only goes over it when what it holds no longer fits.
	if limit := debug.SetMemoryLimit(-1); limit > 0 && limit < math.MaxInt64 && used > uint64(limit) {
		return fmt.Sprintf("it uses %v MiB, over its memory limit of %v MiB", used>>20, limit>>20)
	}
	// A search can take a gigabyte between checks, so stop well before the
	// system's memory is gone: at a tenth of it, and at least 1 GiB.
	if available, total, ok := systemMemory(); ok && available < max(1<<30, total/10) {
		return fmt.Sprintf("the system has only %v MiB of memory left", available>>20)
	}
	return ""
}

// Guarded runs work as a search: once no other search is running, and
// stopped through its context when memory runs short, in which case it
// returns ErrSearchMemory. Waiting for another search ends when ctx does.
func Guarded(ctx context.Context, work func(context.Context) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case searchSlot <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	defer func() { <-searchSlot }()

	if reason := memoryShort(); reason != "" {
		ui.Warn().Msgf("Not starting a search: %v", reason)
		return fmt.Errorf("%w (%v)", ErrSearchMemory, reason)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	done := make(chan struct{})
	defer close(done)
	go func() {
		ticker := time.NewTicker(memoryWatchInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if reason := memoryShort(); reason != "" {
					ui.Warn().Msgf("Stopping a search: %v", reason)
					cancel(fmt.Errorf("%w (%v)", ErrSearchMemory, reason))
					return
				}
			}
		}
	}()
	err := work(ctx)
	if cause := context.Cause(ctx); errors.Is(cause, ErrSearchMemory) {
		// Whatever the search returned, it was cut short for memory.
		return cause
	}
	return err
}

// guardedResolve resolves with resolve as a search (see Guarded).
func guardedResolve[T any](opts ResolverOptions, resolve func(ResolverOptions) (T, error)) (T, error) {
	var result T
	err := Guarded(opts.Context, func(ctx context.Context) error {
		opts.Context = ctx
		var err error
		result, err = resolve(opts)
		return err
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return result, nil
}
