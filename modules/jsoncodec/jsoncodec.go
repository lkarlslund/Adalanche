// Package jsoncodec is the JSON encoder for large outputs such as query
// results: sonic where it runs natively, encoding/json elsewhere. Both
// produce the same output as encoding/json (sorted map keys, HTML escaping).
package jsoncodec

import "io"

// Encoder writes JSON values to a stream.
type Encoder interface {
	SetEscapeHTML(on bool)
	Encode(v any) error
}

// Decoder reads JSON values from a stream.
type Decoder interface {
	UseNumber()
	DisallowUnknownFields()
	Decode(v any) error
}

// Codec is the encoding/json API this package provides.
type Codec interface {
	Marshal(v any) ([]byte, error)
	Unmarshal(data []byte, v any) error
	MarshalIndent(v any, prefix, indent string) ([]byte, error)
	NewEncoder(w io.Writer) Encoder
	NewDecoder(r io.Reader) Decoder
}
