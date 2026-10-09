package collect

import (
	"encoding/xml"
	"errors"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
)

// Logon history is read newest first within this window, up to this many
// events. Busy servers and domain controllers can hold millions of logons.
const (
	logonEventWindow = 90 * 24 * time.Hour
	logonEventLimit  = 250000
	// Availability only reports the last month, day and week.
	availabilityEventWindow = 31 * 24 * time.Hour
	availabilityEventLimit  = 50000
)

var errEventMissingField = errors.New("event is missing a required field")

// systemEvent holds the fields shared by all rendered events. Missing
// elements decode as zero values instead of failing.
type systemEvent struct {
	XMLName xml.Name `xml:"Event"`
	System  struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID string `xml:"EventID"`
		Time    struct {
			Value string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
	} `xml:"System"`
	Data []struct {
		Name  string `xml:"Name,attr"`
		Value string `xml:",chardata"`
	} `xml:"EventData>Data"`
}

func parseSystemEvent(raw []byte) (systemEvent, time.Time, error) {
	var event systemEvent
	if len(raw) > 1<<20 {
		return event, time.Time{}, errAssessmentLimit
	}
	if err := xml.Unmarshal(raw, &event); err != nil {
		return event, time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339Nano, event.System.Time.Value)
	if err != nil {
		return event, time.Time{}, errEventMissingField
	}
	return event, t, nil
}

func (e systemEvent) data(name string) string {
	for _, d := range e.Data {
		if d.Name == name {
			return d.Value
		}
	}
	return ""
}

type logonKey struct {
	User                      string
	LogonType                 uint32
	AuthenticationPackageName string
}

// logonAggregator summarizes successful logon events per user, logon type and
// authentication package.
type logonAggregator struct {
	entries map[logonKey]localmachine.LogonInfo
}

func newLogonAggregator() *logonAggregator {
	return &logonAggregator{entries: map[logonKey]localmachine.LogonInfo{}}
}

// add records one rendered logon event. Events without a time or logon type
// are rejected rather than counted with invented values.
func (a *logonAggregator) add(raw []byte) error {
	event, t, err := parseSystemEvent(raw)
	if err != nil {
		return err
	}
	if event.System.EventID != "4624" {
		return errEventMissingField
	}
	logontype, err := strconv.ParseUint(event.data("LogonType"), 10, 32)
	if err != nil {
		return errEventMissingField
	}
	username := event.data("TargetUserName")
	domain := event.data("TargetDomainName")
	sid := event.data("TargetUserSid")
	pkg := event.data("AuthenticationPackageName")
	if lm := event.data("LmPackageName"); len(lm) > 1 {
		pkg = lm
	}
	ip := event.data("IpAddress")
	if ip == "244.230.0.0" { // Avoid Windows 7 RDP 8.0 bug - https://learn.microsoft.com/en-us/troubleshoot/windows-client/remote/invalid-client-ip-address-port-number-event-4624
		ip = ""
	}

	key := logonKey{User: domain + "/" + username, LogonType: uint32(logontype), AuthenticationPackageName: pkg}
	entry, found := a.entries[key]
	if !found {
		entry = localmachine.LogonInfo{
			User:                      username,
			Domain:                    domain,
			SID:                       sid,
			LogonType:                 uint32(logontype),
			AuthenticationPackageName: pkg,
			FirstSeen:                 t,
			LastSeen:                  t,
		}
	}
	if entry.SID == "" {
		entry.SID = sid
	}
	if t.Before(entry.FirstSeen) {
		entry.FirstSeen = t
	}
	if t.After(entry.LastSeen) {
		entry.LastSeen = t
	}
	if len(ip) > 1 && !slices.Contains(entry.IpAddress, ip) {
		entry.IpAddress = append(entry.IpAddress, ip)
	}
	entry.Count++
	a.entries[key] = entry
	return nil
}

func (a *logonAggregator) logons() []localmachine.LogonInfo {
	return slices.Collect(maps.Values(a.entries))
}

// availabilityTracker turns power and boot events, oldest first, into time
// the machine was running during the last month, week and day.
type availabilityTracker struct {
	now                       time.Time
	laststart, laststop       time.Time
	month, week, day          time.Duration
	monthAgo, weekAgo, dayAgo time.Time
}

func newAvailabilityTracker(now time.Time) *availabilityTracker {
	return &availabilityTracker{
		now:       now,
		laststart: time.Time{}.Add(time.Minute), // The first event may be a shutdown, so assume it was powered on long ago.
		monthAgo:  now.Add(-30 * 24 * time.Hour),
		weekAgo:   now.Add(-7 * 24 * time.Hour),
		dayAgo:    now.Add(-24 * time.Hour),
	}
}

func (a *availabilityTracker) add(raw []byte) error {
	event, t, err := parseSystemEvent(raw)
	if err != nil {
		return err
	}
	provider := event.System.Provider.Name
	switch event.System.EventID {
	case "1": // Resume from sleep
		if provider == "Microsoft-Windows-Power-Troubleshooter" {
			if st, err := time.Parse(time.RFC3339Nano, event.data("SleepTime")); err == nil {
				a.laststop = st
				a.close()
			}
			if wt, err := time.Parse(time.RFC3339Nano, event.data("WakeTime")); err == nil {
				a.laststart = wt
			}
			a.laststart = t
		}
	case "12": // Startup
		if provider == "Microsoft-Windows-Kernel-General" {
			a.laststart = t
		}
	case "13": // Shutdown
		if provider == "Microsoft-Windows-Kernel-General" {
			a.laststop = t
		}
	case "42": // Sleep
		if provider == "Microsoft-Windows-Kernel-Power" {
			a.laststop = t
		}
	case "6008": // Unexpected shutdown
		if provider == "Eventlog" {
			a.laststop = t
		}
	}
	a.close()
	return nil
}

// close registers a completed running interval, if there is one.
func (a *availabilityTracker) close() {
	if !a.laststart.IsZero() && !a.laststop.IsZero() && a.laststart.Before(a.laststop) {
		a.register(a.laststart, a.laststop)
		a.laststart, a.laststop = time.Time{}, time.Time{}
	}
}

func (a *availabilityTracker) register(start, stop time.Time) {
	for _, window := range []struct {
		since time.Time
		total *time.Duration
	}{{a.monthAgo, &a.month}, {a.weekAgo, &a.week}, {a.dayAgo, &a.day}} {
		from := start
		if from.Before(window.since) {
			from = window.since
		}
		if from.Before(stop) {
			*window.total += stop.Sub(from)
		}
	}
}

func (a *availabilityTracker) result() localmachine.Availability {
	if !a.laststart.IsZero() && a.laststop.IsZero() {
		a.register(a.laststart, a.now) // Still running.
	}
	return localmachine.Availability{
		Day:   uint64(a.day.Minutes()),
		Week:  uint64(a.week.Minutes()),
		Month: uint64(a.month.Minutes()),
	}
}
