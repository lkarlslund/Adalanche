//go:build windows

package collect

import (
	"context"
	"errors"
	"testing"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/lkarlslund/adalanche/modules/basedata"
	"golang.org/x/sys/windows"
)

func TestNativeCollectionResults(t *testing.T) {
	for _, tt := range []struct {
		err    error
		status basedata.CollectionStatus
	}{
		{nil, basedata.CollectionCollected},
		{ole.NewError(0x80070005), basedata.CollectionAccessDenied},
		{ole.NewError(0x80041003), basedata.CollectionAccessDenied},
		{ole.NewError(0x80041010), basedata.CollectionUnsupported},
		{ole.NewError(0x80040154), basedata.CollectionUnsupported},
		{errors.ErrUnsupported, basedata.CollectionUnsupported},
		{windows.ERROR_EVT_CHANNEL_NOT_FOUND, basedata.CollectionNotFound},
		{windows.ERROR_TIMEOUT, basedata.CollectionTimedOut},
		{context.DeadlineExceeded, basedata.CollectionTimedOut},
		{context.Canceled, basedata.CollectionCanceled},
		{errAssessmentLimit, basedata.CollectionFailed},
	} {
		if got := nativeCollectionResult(tt.err); got.Status != tt.status {
			t.Errorf("%v = %+v, want %v", tt.err, got, tt.status)
		}
	}
}

func TestLogonSessionNativeLayout(t *testing.T) {
	var data logonDataPrefix
	want := [9]uintptr{88, 4, 16, 32, 48, 64, 68, 72, 80}
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = [9]uintptr{56, 4, 12, 20, 28, 36, 40, 44, 48}
	}
	got := [9]uintptr{unsafe.Sizeof(data), unsafe.Offsetof(data.ID), unsafe.Offsetof(data.User), unsafe.Offsetof(data.Domain), unsafe.Offsetof(data.Authentication), unsafe.Offsetof(data.Type), unsafe.Offsetof(data.Session), unsafe.Offsetof(data.SID), unsafe.Offsetof(data.Time)}
	if got != want {
		t.Fatalf("logon session native layout = %v, want %v", got, want)
	}
	if got := logonID(0xffffffff, -1); got != "ffffffffffffffff" {
		t.Fatal(got)
	}
}

func TestLocalPayloadPaths(t *testing.T) {
	for _, tt := range []struct{ path, dir, want string }{
		{`C:\Scripts\job.ps1`, "", `C:\Scripts\job.ps1`},
		{`job.ps1`, `C:\Scripts`, `C:\Scripts\job.ps1`},
		{`\\server\share\job.ps1`, "", ""},
		{`job.ps1`, "", ""},
		{`%ADALANCHE_TEST_UNDEFINED%\job.ps1`, "", ""},
	} {
		got, err := localPayloadPath(tt.path, tt.dir)
		if got != tt.want || (err != nil) != (tt.want == "") {
			t.Fatalf("path = %q, %v; want %q", got, err, tt.want)
		}
	}
}

func TestNativeScalarProjection(t *testing.T) {
	v := ole.NewVariant(ole.VT_I4, 42)
	got, err := comValue(&v)
	if err != nil || got != int32(42) {
		t.Fatalf("scalar: %v %v", got, err)
	}
	v = ole.NewVariant(ole.VT_NULL, 0)
	if got, err := comValue(&v); err != nil || got != nil {
		t.Fatalf("null: %v %v", got, err)
	}
	v = ole.NewVariant(ole.VT_ARRAY|ole.VT_DISPATCH, 0)
	if _, err := comValue(&v); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatal("allowed provider object array")
	}
}
