//go:build windows

package collect

import (
	"errors"
	"runtime"

	"github.com/go-ole/go-ole"
)

func platformSupported() bool { return true }

func init() {
	prepareThread = prepareWindowsThread
}

// COM state belongs to a thread, so every worker initializes its own.
func prepareWindowsThread(mode ThreadMode) (cleanup func(), comErr error) {
	if mode == ThreadAny {
		return func() {}, nil
	}
	runtime.LockOSThread()
	if mode != ThreadCOM {
		return runtime.UnlockOSThread, nil
	}
	err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	var oleErr *ole.OleError
	if err == nil || (errors.As(err, &oleErr) && oleErr.Code() == 1) {
		return func() {
			ole.CoUninitialize()
			runtime.UnlockOSThread()
		}, nil
	}
	if errors.As(err, &oleErr) && uint32(oleErr.Code()) == 0x80010106 {
		err = nil // The thread already joined another apartment.
	}
	return runtime.UnlockOSThread, err
}
