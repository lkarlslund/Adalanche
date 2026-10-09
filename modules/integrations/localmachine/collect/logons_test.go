package collect

import (
	"fmt"
	"testing"
	"time"
)

func logonEventXML(id, when, logontype, user, ip string) []byte {
	return fmt.Appendf(nil, `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>%s</EventID><TimeCreated SystemTime="%s"/></System><EventData>`+
		`<Data Name="TargetUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="TargetUserName">%s</Data><Data Name="TargetDomainName">EXAMPLE</Data>`+
		`<Data Name="LogonType">%s</Data><Data Name="AuthenticationPackageName">Kerberos</Data><Data Name="LmPackageName">-</Data><Data Name="IpAddress">%s</Data></EventData></Event>`,
		id, when, user, logontype, ip)
}

func TestLogonAggregatorMergesEvents(t *testing.T) {
	a := newLogonAggregator()
	for _, raw := range [][]byte{
		logonEventXML("4624", "2026-09-20T10:00:00.000Z", "3", "alice", "192.0.2.10"),
		logonEventXML("4624", "2026-09-01T10:00:00.000Z", "3", "alice", "192.0.2.11"),
		logonEventXML("4624", "2026-09-10T10:00:00.000Z", "3", "alice", "244.230.0.0"),
		logonEventXML("4624", "2026-09-10T10:00:00.000Z", "10", "alice", "-"),
	} {
		if err := a.add(raw); err != nil {
			t.Fatal(err)
		}
	}
	logons := a.logons()
	if len(logons) != 2 {
		t.Fatalf("got %d entries, want one per logon type", len(logons))
	}
	for _, l := range logons {
		if l.LogonType != 3 {
			continue
		}
		if l.Count != 3 || l.User != "alice" || l.Domain != "EXAMPLE" || l.AuthenticationPackageName != "Kerberos" {
			t.Fatalf("unexpected entry %+v", l)
		}
		if !l.FirstSeen.Equal(time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)) || !l.LastSeen.Equal(time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)) {
			t.Fatalf("unexpected time range %v - %v", l.FirstSeen, l.LastSeen)
		}
		if len(l.IpAddress) != 2 {
			t.Fatalf("addresses %v, want the two real ones", l.IpAddress)
		}
	}
}

func TestLogonAggregatorRejectsIncompleteEvents(t *testing.T) {
	a := newLogonAggregator()
	for name, raw := range map[string][]byte{
		"malformed":  []byte("<Event><System>"),
		"empty":      nil,
		"no time":    logonEventXML("4624", "", "3", "alice", ""),
		"no type":    logonEventXML("4624", "2026-09-20T10:00:00Z", "", "alice", ""),
		"other id":   logonEventXML("4625", "2026-09-20T10:00:00Z", "3", "alice", ""),
		"no data":    []byte(`<Event><System><EventID>4624</EventID><TimeCreated SystemTime="2026-09-20T10:00:00Z"/></System></Event>`),
		"no system":  []byte(`<Event/>`),
		"wrong root": []byte(`<Other/>`),
	} {
		if err := a.add(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if len(a.logons()) != 0 {
		t.Fatal("incomplete events were counted")
	}
}

func availabilityEventXML(provider, id string, when time.Time) []byte {
	return fmt.Appendf(nil, `<Event><System><Provider Name="%s"/><EventID>%s</EventID><TimeCreated SystemTime="%s"/></System></Event>`, provider, id, when.Format(time.RFC3339Nano))
}

func TestAvailabilityTrackerWindows(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	a := newAvailabilityTracker(now)
	for _, raw := range [][]byte{
		// Ran for two hours ten days ago.
		availabilityEventXML("Microsoft-Windows-Kernel-General", "12", now.Add(-10*24*time.Hour)),
		availabilityEventXML("Microsoft-Windows-Kernel-General", "13", now.Add(-10*24*time.Hour+2*time.Hour)),
		// Ran for three hours three days ago.
		availabilityEventXML("Microsoft-Windows-Kernel-General", "12", now.Add(-3*24*time.Hour)),
		availabilityEventXML("Eventlog", "6008", now.Add(-3*24*time.Hour+3*time.Hour)),
		// Running for the last four hours.
		availabilityEventXML("Microsoft-Windows-Kernel-General", "12", now.Add(-4*time.Hour)),
	} {
		if err := a.add(raw); err != nil {
			t.Fatal(err)
		}
	}
	got := a.result()
	if got.Month != 9*60 || got.Week != 7*60 || got.Day != 4*60 {
		t.Fatalf("got %+v minutes, want month 540, week 420, day 240", got)
	}
}
