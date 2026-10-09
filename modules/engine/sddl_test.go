package engine

import "testing"

func TestParseSDDL(t *testing.T) {
	acl, err := ParseSDDL("O:SYG:SYD:PAI(D;;WD;;;BU)(A;CIID;FA;;;SY)(A;;GW;;;S-1-5-21-1-2-3-1001)S:(AU;SA;GA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	if len(acl.Entries) != 3 || !acl.containsdeny || acl.Entries[0].Mask != WRITE_DAC || acl.Entries[1].SID.String() != "S-1-5-18" || acl.Entries[2].Mask != 0x40000000 {
		t.Fatalf("unexpected ACL: %+v", acl)
	}
	if acl.Entries[1].ACEFlags&ACEFLAG_INHERITED_ACE == 0 {
		t.Fatal("lost inheritance flag")
	}
	for _, bad := range []string{"", "O:SY", "D:NO_ACCESS_CONTROL", "D:(A;;GA;;;DA)", "D:(XA;;GA;;;SY)", "D:(A;;GA;;;SY", "D:(A;;ZZ;;;SY)", "D:(A;;GA;;;SY)junk", "D:(A;Q;GA;;;SY)", "D:(A;;GA;guid;;SY)"} {
		if _, err := ParseSDDL(bad); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if acl, err := ParseSDDL("D:"); err != nil || len(acl.Entries) != 0 {
		t.Fatal("empty DACL rejected")
	}
}

func FuzzParseSDDL(f *testing.F) {
	f.Add("D:(A;;FA;;;SY)")
	f.Add("D:(D;;0x2;;;S-1-5-11)")
	f.Fuzz(func(t *testing.T, raw string) { _, _ = ParseSDDL(raw) })
}
