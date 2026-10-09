package frontend

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"

	"github.com/lkarlslund/adalanche/modules/cli"
)

func TestNormalizePreferenceValue(t *testing.T) {
	t.Parallel()

	input := map[any]any{
		"layout": map[any]any{
			"enabled": true,
			1:         "numeric-key",
			"sliders": []int{1, 2, 3},
		},
		"list": []any{
			map[any]any{"nested": "value"},
			[]string{"a", "b"},
			[]bool{true, false},
		},
	}

	got := normalizePreferenceValue(input)
	want := map[string]any{
		"layout": map[string]any{
			"enabled": true,
			"1":       "numeric-key",
			"sliders": []any{1, 2, 3},
		},
		"list": []any{
			map[string]any{"nested": "value"},
			[]any{"a", "b"},
			[]any{true, false},
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalized preferences mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}

func TestPreferencesEndpointsRoundTripNormalizedNestedValues(t *testing.T) {
	tempDir := t.TempDir()
	originalDatapath := *cli.Datapath
	*cli.Datapath = tempDir
	t.Cleanup(func() {
		*cli.Datapath = originalDatapath
	})

	ws := NewWebservice()
	ws.Init(ws.Router)

	payload := map[string]any{
		"organic": map[string]any{
			"enabled": true,
			"sliders": []any{1, 2, 3},
		},
		"cluster": map[string]any{
			"spread": 42,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var expected any
	if err := json.Unmarshal(body, &expected); err != nil {
		t.Fatalf("decode expected request body: %v", err)
	}

	put := httptest.NewRecorder()
	putReq := httptest.NewRequest(http.MethodPut, "/api/preferences/layout", bytes.NewReader(body))
	putReq.Header.Set("Content-Type", "application/json")
	ws.engine.ServeHTTP(put, putReq)
	if put.Code != http.StatusNoContent {
		t.Fatalf("unexpected PUT status %d: %s", put.Code, put.Body.String())
	}

	getOne := httptest.NewRecorder()
	getOneReq := httptest.NewRequest(http.MethodGet, "/api/preferences/layout", nil)
	ws.engine.ServeHTTP(getOne, getOneReq)
	if getOne.Code != http.StatusOK {
		t.Fatalf("unexpected GET key status %d: %s", getOne.Code, getOne.Body.String())
	}

	var gotOne any
	if err := json.Unmarshal(getOne.Body.Bytes(), &gotOne); err != nil {
		t.Fatalf("decode single preference: %v", err)
	}
	if !reflect.DeepEqual(gotOne, expected) {
		t.Fatalf("unexpected single preference body:\n got: %#v\nwant: %#v", gotOne, expected)
	}

	getAll := httptest.NewRecorder()
	getAllReq := httptest.NewRequest(http.MethodGet, "/api/preferences", nil)
	ws.engine.ServeHTTP(getAll, getAllReq)
	if getAll.Code != http.StatusOK {
		t.Fatalf("unexpected GET all status %d: %s", getAll.Code, getAll.Body.String())
	}

	var gotAll map[string]any
	if err := json.Unmarshal(getAll.Body.Bytes(), &gotAll); err != nil {
		t.Fatalf("decode preference map: %v", err)
	}

	layoutValue, found := gotAll["layout"]
	if !found {
		t.Fatalf("expected stored preference in response: %#v", gotAll)
	}
	if !reflect.DeepEqual(layoutValue, expected) {
		t.Fatalf("unexpected stored preference value:\n got: %#v\nwant: %#v", layoutValue, expected)
	}

	dbFile := tempDir + "/persistence.bbolt"
	if _, err := os.Stat(dbFile); err != nil {
		t.Fatalf("expected persistence database at %s: %v", dbFile, err)
	}
}
