package collect

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

func projectRemoteConfiguration(raw string) (map[string]string, error) {
	if len(raw) > 1<<20 {
		return nil, errAssessmentLimit
	}
	r := map[string]string{}
	decoder := xml.NewDecoder(strings.NewReader(raw))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return r, nil
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		switch start.Name.Local {
		case "AllowUnencrypted", "Basic", "Kerberos", "Negotiate", "Certificate", "CredSSP", "Digest", "RootSDDL", "CbtHardeningLevel", "TrustedHosts", "IPv4Filter", "IPv6Filter", "EnableCompatibilityHttpListener", "EnableCompatibilityHttpsListener", "AllowRemoteAccess":
			var value string
			if err := decoder.DecodeElement(&value, &start); err != nil {
				return nil, err
			}
			r[start.Name.Local] = value
		}
	}
}
