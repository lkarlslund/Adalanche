package util

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/lkarlslund/adalanche/modules/ui"

	"github.com/gofrs/uuid"
	"github.com/lkarlslund/stringsplus"
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
				ui.Fatal().Msgf("This isn't working")
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

func ParseBool(input string, defvalue ...bool) (bool, error) {
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
	if len(defvalue) > 0 && err != nil {
		return defvalue[0], err
	}
	return result, err
}

var nolaterthan, _ = time.Parse("20060102", "99991231")

// Filetype converts 100-nanoseconds intervals since Jan 1, 1601 UTC to time.Time
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

func IsPrintableString(s string) bool {
	for _, c := range s {
		if !unicode.IsPrint(c) {
			return false
		}
	}
	return true
}

func Hexify(s string) string {
	var o string
	for _, c := range s {
		if unicode.IsPrint(c) {
			o += string(c)
		} else {
			o += "\\x" + strconv.FormatInt(int64(c), 16)
		}
	}
	return o
}

func Default(values ...string) string {
	for _, value := range values {
		if len(value) != 0 {
			return value
		}
	}
	return ""
}

func StringScrambler(s string) string {
	var result string
	for _, c := range s {
		switch {
		case c == ' ', c == '(', c == '-', c == ')':
			result += string(c)
		case c >= '0' && c <= '9':
			result += string('0' + byte(rand.Intn(9)))
		case c >= 'A' && c <= 'Z':
			result += string('A' + byte(rand.Intn(25)))
		case c >= 'a' && c <= 'z':
			result += string('a' + byte(rand.Intn(25)))
		}
	}
	return result
}

func ExtractNetbiosFromBase(dn string) string {
	elements := strings.Split(dn, ",")
	_, netbios, _ := strings.Cut(elements[0], "=")
	return netbios
}

func ParentDistinguishedName(dn string) string {
	for {
		firstcomma := strings.Index(dn, ",")
		if firstcomma == -1 {
			return "" // At the top
		}
		if firstcomma > 0 {
			if dn[firstcomma-1] == '\\' {
				// False alarm, strip it and go on
				dn = dn[firstcomma+1:]
				continue
			}
		}
		dn = dn[firstcomma+1:]
		break
	}
	return dn
}

func ExtractDomainContextFromDistinguishedName(dn string) string {
	elements := strings.Split(dn, ",")
	last := len(elements)
	first := last // assume we have nothing

	for i := len(elements) - 1; i >= 0; i-- {
		if stringsplus.EqualFoldHasPrefix(elements[i], "dc=") {
			first = i
		} else {
			break
		}
	}

	return strings.ToLower(strings.Join(elements[first:last], ","))
}

func DomainContextToDomainSuffix(dn string) string {
	elements := strings.Split(dn, ",")
	for i, element := range elements {
		elements[i] = strings.TrimPrefix(strings.ToLower(element), "dc=")
	}

	return strings.Join(elements, ".")
}

func DomainSuffixToDomainContext(domain string) string {
	parts := strings.Split(domain, ".")
	return strings.ToLower("dc=" + strings.Join(parts, ",dc="))
}

func ExePath() (string, error) {
	prog := os.Args[0]
	p, err := filepath.Abs(prog)
	if err != nil {
		return "", err
	}
	fi, err := os.Stat(p)
	if err == nil {
		if !fi.Mode().IsDir() {
			return p, nil
		}
		err = fmt.Errorf("%s is directory", p)
	}
	if filepath.Ext(p) == "" {
		p += ".exe"
		fi, err := os.Stat(p)
		if err == nil {
			if !fi.Mode().IsDir() {
				return p, nil
			}
			err = fmt.Errorf("%s is directory", p)
		}
	}
	return "", err
}

func PathExists(name string) bool {
	_, err := os.Stat(name)
	return err == nil // invalid path names on Windows returns strange errors, so just check for nil error
}
