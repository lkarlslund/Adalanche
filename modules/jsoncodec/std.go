//go:build !(amd64 || arm64)

package jsoncodec

import (
	"encoding/json"
	"io"
)

// JSON encodes with encoding/json where sonic does not run.
var JSON Codec = stdCodec{}

type stdCodec struct{}

func (stdCodec) Marshal(v any) ([]byte, error)      { return json.Marshal(v) }
func (stdCodec) Unmarshal(data []byte, v any) error { return json.Unmarshal(data, v) }
func (stdCodec) MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	return json.MarshalIndent(v, prefix, indent)
}
func (stdCodec) NewEncoder(w io.Writer) Encoder { return json.NewEncoder(w) }
func (stdCodec) NewDecoder(r io.Reader) Decoder { return json.NewDecoder(r) }
