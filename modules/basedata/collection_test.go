package basedata

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"syscall"
	"testing"
)

func TestCollectionResultFromError(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want CollectionStatus
	}{
		{"success", nil, CollectionCollected},
		{"absent", fmt.Errorf("read: %w", fs.ErrNotExist), CollectionNotFound},
		{"denied", fmt.Errorf("read: %w", fs.ErrPermission), CollectionAccessDenied},
		{"unsupported", errors.ErrUnsupported, CollectionUnsupported},
		{"canceled", context.Canceled, CollectionCanceled},
		{"timeout", context.DeadlineExceeded, CollectionTimedOut},
		{"failure", errors.New("secret value must not escape"), CollectionFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := CollectionResultFromError(test.err)
			if result.Status != test.want {
				t.Fatalf("got %q, want %q", result.Status, test.want)
			}
			data, err := json.Marshal(result)
			if err != nil || strings.Contains(string(data), "secret") {
				t.Fatalf("unsafe result %s: %v", data, err)
			}
		})
	}
	if got := CollectionResultFromError(fmt.Errorf("wrapped: %w", syscall.Errno(12345))); got.ErrorCode != "errno:12345" {
		t.Fatalf("lost native code: %+v", got)
	}
	if got := (CollectionResults{})["unattempted"].Status; got != CollectionUnknown {
		t.Fatal("missing operation is not unknown")
	}
}
