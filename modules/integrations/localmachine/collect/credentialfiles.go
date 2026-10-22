package collect

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// credentialLocation is a folder in a user profile where Windows keeps
// secrets, and how to count what is in it.
type credentialLocation struct {
	Kind     string // credentials, vault or dpapi-keys
	Relative string // below the profile folder
}

// credentialLocations are what credential-locations reports per profile.
// Credential Manager and the vault hold saved secrets; the DPAPI master keys
// in Protect exist for every profile that has logged on, so they say nothing
// about saved secrets, but their folder is still worth checking for access.
var credentialLocations = []credentialLocation{
	{"credentials", `AppData\Local\Microsoft\Credentials`},
	{"credentials", `AppData\Roaming\Microsoft\Credentials`},
	{"vault", `AppData\Local\Microsoft\Vault`},
	{"dpapi-keys", `AppData\Roaming\Microsoft\Protect`},
}

// countCredentialFiles counts the secrets in a credential location: each file
// directly in a Credentials folder is one saved credential, each .vcrd file
// in a vault's folders is one vault credential, and each file in a Protect
// folder's SID folders is a DPAPI master key. A missing folder holds none.
func countCredentialFiles(kind, dir string) (files int, exists bool, err error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, true, err
	}
	for _, entry := range entries {
		switch kind {
		case "credentials":
			if !entry.IsDir() {
				files++
			}
		case "vault", "dpapi-keys":
			if !entry.IsDir() {
				continue
			}
			inner, innerErr := os.ReadDir(filepath.Join(dir, entry.Name()))
			if innerErr != nil {
				err = innerErr
				continue
			}
			for _, file := range inner {
				if file.IsDir() {
					continue
				}
				if kind == "vault" && !strings.EqualFold(filepath.Ext(file.Name()), ".vcrd") {
					continue
				}
				files++
			}
		}
	}
	return files, true, err
}

// filetimeToTime converts a Windows FILETIME, given as its two halves as the
// registry keeps them, to a time; zero for none.
func filetimeToTime(high, low uint64) time.Time {
	ft := high<<32 | low&0xffffffff
	const unixEpoch = 116444736000000000 // 1970-01-01 in 100ns intervals since 1601
	if ft <= unixEpoch {
		return time.Time{}
	}
	return time.Unix(0, int64(ft-unixEpoch)*100).UTC()
}
