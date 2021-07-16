package main

import (
	"regexp"
	"strconv"
	"time"
	"unicode"

	"github.com/gofrs/uuid"
	"github.com/rs/zerolog/log"
	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

var legalMatch = regexp.MustCompile("[[:alnum:] _.=,-]") // dash must be LAST! doh

func cleanfilename(input string) string {
	normalized, _, _ := transform.String(transform.Chain(norm.NFD, transform.RemoveFunc(func(r rune) bool {
		return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
	}), norm.NFC), input)

	var output string

	for _, chr := range normalized {
		if legalMatch.MatchString(string(chr)) {
			if chr == '*' || chr == '/' {
				log.Fatal().Msgf("This isnt working")
			}
			output += string(chr)
		}
	}
	return output
}

func SwapUUIDEndianess(u uuid.UUID) uuid.UUID {
	var r uuid.UUID
	r[0], r[1], r[2], r[3] = u[3], u[2], u[1], u[0]
	r[4], r[5] = u[5], u[4]
	r[6], r[7] = u[7], u[6]
	copy(r[8:], u[8:])
	return r
}

func StringInSlice(needle string, haystack []string) bool {
	for _, hay := range haystack {
		if hay == needle {
			return true
		}
	}
	return false
}

func ParseBool(input string) (bool, error) {
	result, err := strconv.ParseBool(input)
	if err == nil {
		return result, err
	}
	switch input {
	case "on", "On":
		return true, nil
	case "off", "Off":
		return false, nil
	}
	return result, err
}

var nolaterthan, _ = time.Parse("20060102", "99991231")

func FiletimeToTime(filetime uint64) time.Time {
	// We assume that a zero time is a blank time
	if filetime == 0 || filetime == 0xFFFFFFFFFFFFFFFF {
		return time.Time{}
	}

	// First convert 100-ns intervals to microseconds, then adjust for the epoch difference
	unixsec := int64((filetime / 10000000) - 11644473600)
	unixns := int64((filetime * 10) % 1000000000)

	t := time.Unix(unixsec, unixns)

	if t.After(nolaterthan) {
		t = nolaterthan
	}

	return t
}

func IsASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func Default(values ...string) string {
	for _, value := range values {
		if len(value) > 0 {
			return value
		}
	}
	return ""
}
