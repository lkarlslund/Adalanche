//go:build windows

package collect

import (
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	assessmentEventDLL  = windows.NewLazySystemDLL("wevtapi.dll")
	assessmentEvtQuery  = assessmentEventDLL.NewProc("EvtQuery")
	assessmentEvtNext   = assessmentEventDLL.NewProc("EvtNext")
	assessmentEvtRender = assessmentEventDLL.NewProc("EvtRender")
	assessmentEvtClose  = assessmentEventDLL.NewProc("EvtClose")
)

func collectPasswordEvents(c *assessmentCapture) error {
	c.data.Scope = "local-password-management-events:last-30-days:max-100"
	return collectNativeEvents(c, "Microsoft-Windows-LAPS/Operational", "*[System[TimeCreated[timediff(@SystemTime) <= 2592000000] and (EventID=10003 or EventID=10004 or EventID=10005 or EventID=10018 or EventID=10019 or EventID=10020 or EventID=10021 or EventID=10022 or EventID=10023 or EventID=10027 or EventID=10029 or EventID=10031)]]", 100)
}

func collectLSAProtectionEvents(c *assessmentCapture) error {
	boot := time.Now().Add(-windows.DurationSinceBoot()).UTC().Format(time.RFC3339Nano)
	query := fmt.Sprintf("*[System[Provider[@Name='Microsoft-Windows-Wininit'] and EventID=12 and TimeCreated[@SystemTime>='%s']]]", boot)
	return collectNativeEvents(c, "System", query, 1)
}

func collectNativeEvents(c *assessmentCapture, channel, query string, limit int) error {
	truncated, err := readNativeEvents(c.ctx, channel, query, evtQueryReverseDirection, limit, func(raw string) error {
		record, err := projectAssessmentEvent(raw, channel == "Microsoft-Windows-LAPS/Operational")
		if err != nil {
			return err
		}
		return c.add(record)
	})
	if truncated {
		c.data.Truncated = true // The requested newest-N window is not a complete log.
	}
	return err
}

const (
	evtQueryChannelPath      = 0x1
	evtQueryForwardDirection = 0x100
	evtQueryReverseDirection = 0x200
	evtBatchSize             = 64
)

// readNativeEvents renders at most limit events matching query and passes
// each one to visit. It reports truncation when more events remain.
func readNativeEvents(ctx context.Context, channel, query string, direction uintptr, limit int, visit func(string) error) (truncated bool, err error) {
	for _, proc := range []*windows.LazyProc{assessmentEvtQuery, assessmentEvtNext, assessmentEvtRender, assessmentEvtClose} {
		if err := proc.Find(); err != nil {
			return false, errors.ErrUnsupported
		}
	}
	channelName, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return false, err
	}
	xpath, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return false, err
	}
	handle, _, err := assessmentEvtQuery.Call(0, uintptr(unsafe.Pointer(channelName)), uintptr(unsafe.Pointer(xpath)), evtQueryChannelPath|direction)
	if handle == 0 {
		return false, err
	}
	defer assessmentEvtClose.Call(handle)
	var buffer []uint16
	count := 0
	for {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		var events [evtBatchSize]uintptr
		var returned uint32
		ok, _, err := assessmentEvtNext.Call(handle, evtBatchSize, uintptr(unsafe.Pointer(&events[0])), 1000, 0, uintptr(unsafe.Pointer(&returned)))
		if ok == 0 {
			if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
				return false, nil
			}
			if errors.Is(err, windows.ERROR_TIMEOUT) {
				return false, context.DeadlineExceeded
			}
			return false, err
		}
		if returned == 0 || returned > evtBatchSize {
			return false, errors.ErrUnsupported
		}
		var visitErr error
		for i := range int(returned) {
			if visitErr == nil {
				if count >= limit {
					truncated = true
				} else {
					var raw string
					raw, buffer, visitErr = renderNativeEvent(events[i], buffer)
					if visitErr == nil {
						visitErr = visit(raw)
					}
					count++
				}
			}
			assessmentEvtClose.Call(events[i]) // Close every returned handle, even after an error.
		}
		if visitErr != nil {
			return false, visitErr
		}
		if truncated {
			return true, nil
		}
	}
}

func renderNativeEvent(event uintptr, buffer []uint16) (string, []uint16, error) {
	var used, properties uint32
	ok, _, err := assessmentEvtRender.Call(0, event, 1, 0, 0, uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 && !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return "", buffer, err
	}
	if used == 0 || used > 1<<20 {
		return "", buffer, errAssessmentLimit
	}
	if need := int(used+1) / 2; cap(buffer) < need {
		buffer = make([]uint16, need)
	} else {
		buffer = buffer[:need]
	}
	ok, _, err = assessmentEvtRender.Call(0, event, 1, uintptr(len(buffer)*2), uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&properties)))
	if ok == 0 {
		return "", buffer, err
	}
	return windows.UTF16ToString(buffer), buffer, nil
}
