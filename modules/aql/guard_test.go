package aql

import (
	"context"
	"errors"
	"math"
	"runtime"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// shortAfter makes memory run short from the nth check on (1 is the check
// before a search starts), and restores the real check after the test.
func shortAfter(t *testing.T, n int32) {
	t.Helper()
	var checks atomic.Int32
	memoryShort = func() string {
		if checks.Add(1) >= n {
			return "test says so"
		}
		return ""
	}
	t.Cleanup(func() { memoryShort = memoryShortNow })
}

func TestSearchesRunOneAtATime(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	first := make(chan error)
	go func() {
		first <- Guarded(context.Background(), func(context.Context) error {
			close(started)
			<-release
			return nil
		})
	}()
	<-started

	var secondRan atomic.Bool
	second := make(chan error)
	go func() {
		second <- Guarded(context.Background(), func(context.Context) error {
			secondRan.Store(true)
			return nil
		})
	}()
	time.Sleep(50 * time.Millisecond)
	if secondRan.Load() {
		t.Fatal("a second search ran while the first was running")
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil || !secondRan.Load() {
		t.Fatalf("second search: ran %v, %v", secondRan.Load(), err)
	}

	// Waiting for the slot ends with the caller's context.
	hold := make(chan struct{})
	holding := make(chan struct{})
	go Guarded(context.Background(), func(context.Context) error { close(holding); <-hold; return nil })
	<-holding
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := Guarded(ctx, func(context.Context) error { t.Error("ran without the slot"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("waiting caller: %v", err)
	}
	close(hold)
}

// The watchdog stops a running search when memory runs short.
func TestWatchdogStopsSearch(t *testing.T) {
	shortAfter(t, 2) // fine at the start, short at the first check while running
	err := Guarded(context.Background(), func(ctx context.Context) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
			return errors.New("not stopped")
		}
	})
	if !errors.Is(err, ErrSearchMemory) || !strings.Contains(err.Error(), "test says so") {
		t.Fatalf("got %v", err)
	}
}

// A search is not started when memory is already short.
func TestNoSearchWhenMemoryShort(t *testing.T) {
	shortAfter(t, 1)
	err := Guarded(context.Background(), func(context.Context) error {
		t.Error("search ran")
		return nil
	})
	if !errors.Is(err, ErrSearchMemory) {
		t.Fatalf("got %v", err)
	}
}

// Queries, unions included, run as guarded searches.
func TestQueriesAreGuarded(t *testing.T) {
	tg := newTransitGraph([]string{"S>A>E"}, nil)
	union, err := ParseAQLQuery("start:(name=S)-[]{1,3}->end:(name=E) UNION start:(name=A)-[]{1}->end:(name=E)", tg.g)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error)
	go func() {
		_, err := union.Resolve(NewResolverOptions())
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a union deadlocked on the search slot")
	}

	shortAfter(t, 1)
	if _, err := union.Resolve(NewResolverOptions()); !errors.Is(err, ErrSearchMemory) {
		t.Fatalf("union with memory short: %v", err)
	}
	q, _ := ParseAQLQuery("start:(name=S)-[]{1,3}->end:(name=E)", tg.g)
	if _, err := q.Resolve(NewResolverOptions()); !errors.Is(err, ErrSearchMemory) {
		t.Fatalf("query with memory short: %v", err)
	}
}

// The real check finds a process over its memory limit, and reads the
// system's memory where it can.
func TestMemoryShortNow(t *testing.T) {
	old := debug.SetMemoryLimit(-1)
	defer debug.SetMemoryLimit(old)

	debug.SetMemoryLimit(math.MaxInt64)
	if available, total, ok := systemMemory(); ok && available > max(2<<30, total/5) {
		if reason := memoryShortNow(); reason != "" {
			t.Errorf("with no limit and %v MiB free: %v", available>>20, reason)
		}
	}
	debug.SetMemoryLimit(1 << 20) // 1 MiB: far below what any process uses
	if reason := memoryShortNow(); !strings.Contains(reason, "memory limit") {
		t.Errorf("over the limit: %q", reason)
	}
	if runtime.GOOS == "linux" {
		available, total, ok := systemMemory()
		if !ok || total == 0 || available == 0 || available > total {
			t.Errorf("system memory: %v of %v, %v", available, total, ok)
		}
	}
}

// A stopped search returns its context's error, not a result, in REACH and
// in the enumerating modes.
func TestStoppedSearchesReturnErrors(t *testing.T) {
	tg := newTransitGraph([]string{"S>A>B>C>E", "S>D>E"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, mode := range []string{"REACH", "ACYCLIC"} {
		q, err := ParseAQLQuery(mode+" start:(name=S)-[]{1,6}->end:(name=E)", tg.g)
		if err != nil {
			t.Fatal(err)
		}
		opts := NewResolverOptions()
		opts.Context = ctx
		if result, err := q.Resolve(opts); err == nil {
			t.Errorf("%v: stopped search gave a result of %v nodes", mode, result.Order())
		}
	}
}
