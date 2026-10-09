package smoke

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebSmoke(t *testing.T) {
	t.Parallel()

	sampleDataDir := os.Getenv("ADALANCHE_SAMPLEDATA")
	if sampleDataDir == "" {
		sampleDataDir = "/home/lak/github-repos/adalanche-sampledata/goad"
	}
	if stat, err := os.Stat(sampleDataDir); err != nil || !stat.IsDir() {
		t.Skipf("sample data directory unavailable: %s", sampleDataDir)
	}

	rootDir := repoRoot(t)
	binPath := filepath.Join(t.TempDir(), "adalanche")

	buildCmd := exec.Command("go", "build", "-o", binPath, "./adalanche")
	buildCmd.Dir = rootDir
	buildOutput, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(buildOutput))
	}

	port := freePort(t)
	bindAddr := fmt.Sprintf("127.0.0.1:%d", port)
	baseURL := "http://" + bindAddr

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var serverLog bytes.Buffer
	serverCmd := exec.CommandContext(ctx, binPath, "--datapath", sampleDataDir, "analyze", "--bind", bindAddr, "--nobrowser")
	serverCmd.Dir = rootDir
	serverCmd.Stdout = &serverLog
	serverCmd.Stderr = &serverLog
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start adalanche: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- serverCmd.Wait()
	}()

	t.Cleanup(func() {
		quitClient := &http.Client{Timeout: 2 * time.Second}
		req, err := http.NewRequest(http.MethodGet, baseURL+"/api/backend/quit", nil)
		if err == nil {
			_, _ = quitClient.Do(req)
		}

		select {
		case <-time.After(3 * time.Second):
			cancel()
		case <-done:
			return
		}

		select {
		case <-time.After(3 * time.Second):
		case <-done:
		}
	})

	waitForHTTP(t, done, &serverLog, baseURL+"/api/backend/status", 60*time.Second)

	readyClient := &http.Client{Timeout: 3 * time.Minute}
	if _, err := getBody(readyClient, baseURL+"/api/backend/await/Ready"); err != nil {
		t.Fatalf("await ready failed: %v\n%s", err, serverLog.String())
	}

	defaultClient := &http.Client{Timeout: 10 * time.Second}

	rootHTML, err := getBody(defaultClient, baseURL+"/")
	if err != nil {
		t.Fatalf("failed to fetch root page: %v\n%s", err, serverLog.String())
	}
	if !strings.Contains(rootHTML, "Adalanche") {
		t.Fatalf("root page does not look like Adalanche\n%s", rootHTML)
	}

	var status struct {
		Status string `json:"status"`
	}
	if err := getJSON(defaultClient, baseURL+"/api/backend/status", &status); err != nil {
		t.Fatalf("status endpoint failed: %v\n%s", err, serverLog.String())
	}
	if status.Status != "Ready" {
		t.Fatalf("unexpected status payload: %+v", status)
	}

	var filters struct {
		ObjectTypes []json.RawMessage `json:"objecttypes"`
		Edges       []json.RawMessage `json:"edges"`
	}
	if err := getJSON(defaultClient, baseURL+"/api/backend/filteroptions", &filters); err != nil {
		t.Fatalf("filteroptions failed: %v\n%s", err, serverLog.String())
	}
	if len(filters.ObjectTypes) == 0 {
		t.Fatal("filteroptions returned no object types")
	}
	if len(filters.Edges) == 0 {
		t.Fatal("filteroptions returned no edges")
	}

	var statistics struct {
		Adalanche  map[string]string `json:"adalanche"`
		Statistics map[string]int    `json:"statistics"`
	}
	if err := getJSON(defaultClient, baseURL+"/api/backend/statistics", &statistics); err != nil {
		t.Fatalf("statistics failed: %v\n%s", err, serverLog.String())
	}
	if statistics.Adalanche["status"] != "Ready" {
		t.Fatalf("statistics endpoint not ready: %+v", statistics)
	}
	if statistics.Statistics["Nodes"] <= 0 {
		t.Fatalf("statistics endpoint returned no nodes: %+v", statistics)
	}
	if statistics.Statistics["Edges"] <= 0 {
		t.Fatalf("statistics endpoint returned no edges: %+v", statistics)
	}

	var validate struct {
		Success bool `json:"success"`
	}
	if err := getJSON(defaultClient, baseURL+"/api/backend/validatequery?query=%28objectClass%3D*%29", &validate); err != nil {
		t.Fatalf("validatequery failed: %v\n%s", err, serverLog.String())
	}
	if !validate.Success {
		t.Fatalf("validatequery unexpectedly failed: %+v", validate)
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	rootDir := filepath.Clean(filepath.Join(wd, "..", ".."))
	if _, err := os.Stat(filepath.Join(rootDir, "go.mod")); err != nil {
		t.Fatalf("failed to locate repo root from %s: %v", wd, err)
	}
	return rootDir
}

func freePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to allocate free port: %v", err)
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port
}

func waitForHTTP(t *testing.T, done <-chan error, serverLog *bytes.Buffer, url string, timeout time.Duration) {
	t.Helper()

	client := &http.Client{Timeout: 2 * time.Second}
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("adalanche exited before becoming ready: %v\n%s", err, serverLog.String())
		default:
		}

		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			return
		}

		time.Sleep(500 * time.Millisecond)
	}

	t.Fatalf("timed out waiting for %s\n%s", url, serverLog.String())
}

func getBody(client *http.Client, url string) (string, error) {
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected HTTP %d from %s: %s", resp.StatusCode, url, string(body))
	}
	return string(body), nil
}

func getJSON(client *http.Client, url string, target any) error {
	body, err := getBody(client, url)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(body), target)
}
