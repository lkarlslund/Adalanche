package dedup

import "unique"

var D Unique

type Unique struct {
	// uses the Go 1.23 unique package
}

func (u *Unique) BS(b []byte) string {
	return unique.Make(string(b)).Value()
}

func (u *Unique) S(s string) string {
	return unique.Make(s).Value()
}

func (u *Unique) Flush() {
	// noop
}
