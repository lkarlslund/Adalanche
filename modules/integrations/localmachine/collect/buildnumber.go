package collect

import (
	"errors"
	"strconv"

	"github.com/lkarlslund/adalanche/modules/basedata"
)

const currentVersionPath = `HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion`

// Keep a readable base build when the revision is unavailable, while recording
// both outcomes. A successful zero revision is distinct from a failed read.
func collectBuildNumber(readValue registryValueReader, readDWORD func(string) (uint32, error), outcomes basedata.CollectionResults) string {
	buildValue, buildErr := readValue(currentVersionPath + `\CurrentBuildNumber`)
	build, ok := buildValue.(string)
	if buildErr == nil && !ok {
		buildErr = errors.ErrUnsupported
	}
	if buildErr == nil {
		if _, err := strconv.ParseUint(build, 10, 32); err != nil {
			buildErr = errors.ErrUnsupported
		}
	}
	outcomes["registry/value/"+currentVersionPath+`\CurrentBuildNumber`] = basedata.CollectionResultFromError(buildErr)
	revision, revisionErr := readDWORD(currentVersionPath + `\UBR`)
	outcomes["registry/value/"+currentVersionPath+`\UBR`] = basedata.CollectionResultFromError(revisionErr)
	if buildErr != nil {
		return ""
	}
	if revisionErr != nil {
		return build
	}
	return build + "." + strconv.FormatUint(uint64(revision), 10)
}
