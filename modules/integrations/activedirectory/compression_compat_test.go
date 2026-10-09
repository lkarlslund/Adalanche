package activedirectory

import (
	"bytes"
	"encoding/hex"
	"github.com/pierrec/lz4/v4"
	"io"
	"strings"
	"testing"
)

// This frame was written by the legacy collector with block checksums enabled.
// Keep it fixed: regenerating it with a new writer hides format incompatibilities.
const legacyDumpFrame = "04224d1874708e2c000000ff0773796e7468657469632d64756d702d7265636f72640a1600ffff8be0632d64756d702d7265636f72640a31531d550000000031531d55"

func TestLegacyDumpCompressionCompatibility(t *testing.T) {
	t.Parallel()
	frame, err := hex.DecodeString(legacyDumpFrame)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(lz4.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatalf("decode legacy dump frame: %v", err)
	}
	if want := strings.Repeat("synthetic-dump-record\n", 32); string(got) != want {
		t.Fatal("legacy dump contents changed")
	}
	frame[15] ^= 1
	if _, err := io.ReadAll(lz4.NewReader(bytes.NewReader(frame))); err == nil {
		t.Fatal("corrupted frame was accepted")
	}
}
