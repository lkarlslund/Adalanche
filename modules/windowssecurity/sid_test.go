package windowssecurity

import (
	"reflect"
	"testing"
)

func TestServiceNameToServiceSID(t *testing.T) {
	tests := []struct {
		service string
		want    SID
	}{
		{
			service: "msiserver",
			want:    MustParseStringSID("S-1-5-80-685333868-2237257676-1431965530-1907094206-2438021966"),
		},
		{
			service: "RtkAudioUniversalService",
			want:    MustParseStringSID("S-1-5-80-1164333642-2394958904-2405857294-3413162929-38257115"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			if got := ServiceNameToServiceSID(tt.service); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ServiceNameToServiceSID() = %v, want %v", got.String(), tt.want.String())
			}
		})
	}
}

func TestSIDAddComponent(t *testing.T) {
	domain := MustParseStringSID("S-1-5-21-1-2-3")
	if got, want := domain.AddComponent(513), MustParseStringSID("S-1-5-21-1-2-3-513"); got != want {
		t.Fatalf("AddComponent gives %v, want %v", got, want)
	}
	if got := MustParseStringSID("S-1-5-21-1-2-3-1001").StripRID().AddComponent(513).String(); got != "S-1-5-21-1-2-3-513" {
		t.Fatalf("replacing the RID gives %v", got)
	}
}
