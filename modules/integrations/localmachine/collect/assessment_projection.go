package collect

import (
	"encoding/xml"
	"errors"
	"io"
	"strings"
)

// Unquoted paths containing spaces are ambiguous. Do not turn command arguments
// into a guessed file name or persist the command line itself.
func startupExecutable(command string) string {
	command = strings.TrimSpace(command)
	var executable string
	if strings.HasPrefix(command, `"`) {
		end := strings.IndexByte(command[1:], '"')
		if end < 0 {
			return ""
		}
		executable = command[1 : 1+end]
	} else {
		executable, _, _ = strings.Cut(command, " ")
		if strings.ContainsAny(executable, "\t\r\n") {
			return ""
		}
	}
	if !strings.HasSuffix(strings.ToLower(executable), ".exe") {
		return ""
	}
	return executable
}

// Project only configuration fields. Never retain complete plugin XML, which
// can contain credentials. Preserve separate ACLs rather than choosing one.
func wsmanRecord(raw, kind string) (map[string]any, error) {
	if len(raw) > 1<<20 {
		return nil, errAssessmentLimit
	}
	record := map[string]any{}
	decoder := xml.NewDecoder(strings.NewReader(raw))
	var security []map[string]string
	resource := ""
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			if len(security) > 0 {
				record["Security"] = security
			}
			if len(security) == 1 {
				record["SecurityDescriptorSddl"] = security[0]["Sddl"]
			}
			return record, nil
		}
		if err != nil {
			return nil, err
		}
		if end, ok := token.(xml.EndElement); ok && end.Name.Local == "Resource" {
			resource = ""
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if kind == "listener" {
			switch start.Name.Local {
			case "Address", "Transport", "Port", "Enabled", "URLPrefix", "CertificateThumbprint":
				var value string
				if err := decoder.DecodeElement(&value, &start); err != nil {
					return nil, err
				}
				record[start.Name.Local] = value
			}
		} else {
			entry := map[string]string{"ResourceURI": resource}
			for _, attribute := range start.Attr {
				if start.Name.Local == "PlugInConfiguration" && (attribute.Name.Local == "Name" || attribute.Name.Local == "RunAsUser") {
					record[attribute.Name.Local] = attribute.Value
				}
				if start.Name.Local == "Resource" && attribute.Name.Local == "ResourceUri" {
					resource = attribute.Value
				}
				if start.Name.Local == "Security" && (attribute.Name.Local == "Sddl" || attribute.Name.Local == "Uri" || attribute.Name.Local == "ExactMatch") {
					entry[attribute.Name.Local] = attribute.Value
				}
			}
			if start.Name.Local == "Security" {
				security = append(security, entry)
			}
		}
	}
}
