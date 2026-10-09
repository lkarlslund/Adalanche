package basedata

import (
	"context"
	"errors"
	"io/fs"
	"strconv"
	"syscall"
)

// CollectionResultFromError preserves acquisition failures without serializing
// arbitrary error text. Callers must retain partial data separately on failure.
func CollectionResultFromError(err error) CollectionResult {
	r := CollectionResult{Status: CollectionCollected}
	if err == nil {
		return r
	}
	r.Status = CollectionFailed
	switch {
	case errors.Is(err, fs.ErrNotExist):
		r.Status = CollectionNotFound
	case errors.Is(err, fs.ErrPermission):
		r.Status = CollectionAccessDenied
	case errors.Is(err, errors.ErrUnsupported):
		r.Status = CollectionUnsupported
	case errors.Is(err, context.Canceled):
		r.Status = CollectionCanceled
	case errors.Is(err, context.DeadlineExceeded):
		r.Status = CollectionTimedOut
	}
	var code syscall.Errno
	if errors.As(err, &code) {
		r.ErrorCode = "errno:" + strconv.FormatUint(uint64(code), 10)
	}
	return r
}
