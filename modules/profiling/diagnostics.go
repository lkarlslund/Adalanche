package profiling

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	httppprof "net/http/pprof"
	"runtime"
	"runtime/trace"
	"sync"
	"time"

	"github.com/lkarlslund/adalanche/modules/engine"
	"github.com/lkarlslund/adalanche/modules/ui"
)

func memoryHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	// No forced GC, object identifiers, or recursive graph traversal here.
	_ = json.NewEncoder(w).Encode(struct {
		Runtime        runtime.MemStats         `json:"runtime"`
		Graph          *engine.MemoryStatistics `json:"graph_at_finalization"`
		MemProfileRate int                      `json:"memory_profile_sample_bytes"`
	}{stats, engine.LatestMemoryStatistics(), runtime.MemProfileRate})
}

func (s *session) startDiagnostics(o Options) error {
	if o.BlockProfileRate < 0 || o.MutexProfileFraction < 0 {
		return fmt.Errorf("profiling sample rates must be nonnegative")
	}
	if o.FlightRecorder && !o.EmbeddedProfiler {
		return fmt.Errorf("flight recorder requires embeddedprofiler for snapshot access")
	}
	if o.FlightRecorder && (o.FlightRecorderBytes < 1<<20 || o.FlightRecorderBytes > 256<<20 || o.FlightRecorderAge <= 0 || o.FlightRecorderAge > time.Hour) {
		return fmt.Errorf("flight recorder requires 1–256 MiB and an age between zero and one hour")
	}
	if o.BlockProfileRate > 0 {
		runtime.SetBlockProfileRate(o.BlockProfileRate)
		s.addControl(0, func() { runtime.SetBlockProfileRate(0) })
	}
	if o.MutexProfileFraction > 0 {
		previous := runtime.SetMutexProfileFraction(o.MutexProfileFraction)
		s.addControl(0, func() { runtime.SetMutexProfileFraction(previous) })
	}
	if !o.EmbeddedProfiler {
		return nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", httppprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", httppprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", httppprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", httppprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", httppprof.Trace)
	mux.HandleFunc("/debug/memory", memoryHandler)
	if o.FlightRecorder {
		recorder := trace.NewFlightRecorder(trace.FlightRecorderConfig{MaxBytes: o.FlightRecorderBytes, MinAge: o.FlightRecorderAge})
		if err := recorder.Start(); err != nil {
			return fmt.Errorf("start flight recorder: %w", err)
		}
		var mu sync.Mutex
		s.addControl(0, func() { mu.Lock(); defer mu.Unlock(); recorder.Stop() })
		mux.HandleFunc("/debug/flightrecorder", func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			if !mu.TryLock() {
				http.Error(w, "snapshot busy", http.StatusTooManyRequests)
				return
			}
			defer mu.Unlock()
			if !recorder.Enabled() {
				http.Error(w, "recorder stopped", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Cache-Control", "no-store")
			if _, err := recorder.WriteTo(w); err != nil {
				ui.Warn().Msg("Flight recorder snapshot failed")
			}
		})
	}
	var listener net.Listener
	var err error
	for port := 6060; port < 6070; port++ {
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("bind profiling listener: %w", err)
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 2 * time.Minute, IdleTimeout: 30 * time.Second}
	s.addControl(0, func() { _ = server.Close() })
	engine.EnableMemoryStatistics(true)
	s.addControl(0, func() { engine.EnableMemoryStatistics(false) })
	s.address = listener.Addr().String()
	ui.Info().Msgf("Profiling listener started on %s", listener.Addr())
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			ui.Warn().Msg("Profiling listener stopped unexpectedly")
		}
	}()
	return nil
}
