package mcpserver

import "testing"

func TestStrictRedaction(t *testing.T) {
	r, err := newRedactor("strict")
	if err != nil {
		t.Fatalf("newRedactor failed: %v", err)
	}

	masked, ok := r.mask("unicodePwd", []string{"secret"})
	if !ok {
		t.Fatalf("expected unicodePwd to be redacted")
	}
	if len(masked) != 1 || masked[0] != "<redacted>" {
		t.Fatalf("unexpected masked value: %#v", masked)
	}

	plain, ok := r.mask("displayName", []string{"Ada"})
	if ok {
		t.Fatalf("did not expect displayName to be redacted")
	}
	if len(plain) != 1 || plain[0] != "Ada" {
		t.Fatalf("unexpected plain value: %#v", plain)
	}
}

func TestClampLimit(t *testing.T) {
	if got := clampLimit(0); got != defaultFindLimit {
		t.Fatalf("default limit mismatch: got %d want %d", got, defaultFindLimit)
	}
	if got := clampLimit(maxResultLimit + 50); got != maxResultLimit {
		t.Fatalf("max limit mismatch: got %d want %d", got, maxResultLimit)
	}
}
