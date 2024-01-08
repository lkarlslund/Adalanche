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
