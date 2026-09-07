package profiling

import (
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticsLifecycle(t *testing.T) {
	options := Options{EmbeddedProfiler: true, FlightRecorder: true, FlightRecorderBytes: 1 << 20, FlightRecorderAge: time.Second, MutexProfileFraction: 5, BlockProfileRate: 1000000}
	previous := runtime.SetMutexProfileFraction(-1)
	if err := Start(options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(StopAll)
	address := currentSession.address
	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/debug/memory", "/debug/pprof/", "/debug/flightrecorder"} {
		response, err := client.Get("http://" + address + path)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d, error %v", path, response.StatusCode, err)
		}
		if path == "/debug/memory" && !json.Valid(body) {
			t.Fatal("invalid memory JSON")
		}
		if path == "/debug/pprof/" && !strings.Contains(string(body), "goroutineleak") {
			t.Fatal("leak profile not exposed")
		}
		if path == "/debug/flightrecorder" && !strings.HasPrefix(string(body), "go 1.") {
			t.Fatal("invalid trace header")
		}
	}
	if err := Start(options); err == nil {
		t.Fatal("allowed overlapping sessions")
	}
	StopAll()
	if runtime.SetMutexProfileFraction(-1) != previous {
		t.Fatal("mutex sampling not restored")
	}
	if response, err := client.Get("http://" + address + "/debug/memory"); err == nil {
		response.Body.Close()
		t.Fatal("listener still open")
	}
}

func TestDiagnosticsValidationAndRollback(t *testing.T) {
	for _, options := range []Options{{FlightRecorder: true}, {BlockProfileRate: -1}, {MutexProfileFraction: -1}, {EmbeddedProfiler: true, FlightRecorder: true}} {
		if err := Start(options); err == nil {
			StopAll()
			t.Fatal("accepted invalid options")
		}
	}
	previous := runtime.SetMutexProfileFraction(-1)
	err := Start(Options{MutexProfileFraction: 7, CPUProfile: true, Datapath: t.TempDir() + "/missing"})
	if err == nil {
		StopAll()
		t.Fatal("expected output creation failure")
	}
	if runtime.SetMutexProfileFraction(-1) != previous {
		t.Fatal("startup failure leaked profiling state")
	}
}
