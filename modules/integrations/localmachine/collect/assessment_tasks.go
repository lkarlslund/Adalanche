package collect

import (
	"encoding/xml"
	"errors"
	"strings"
)

type taskPayloadDescription struct {
	XMLName    xml.Name `xml:"Task"`
	Principals []struct {
		UserID              string `xml:"UserId"`
		GroupID             string `xml:"GroupId"`
		LogonType, RunLevel string
	} `xml:"Principals>Principal"`
	Executables []struct{ Command, Arguments, WorkingDirectory string } `xml:"Actions>Exec"`
	Handlers    []struct {
		ClassID string `xml:"ClassId"`
	} `xml:"Actions>ComHandler"`
}

func parseTaskPayloads(raw string) (taskPayloadDescription, error) {
	var task taskPayloadDescription
	if len(raw) > 1<<20 {
		return task, errAssessmentLimit
	}
	if err := xml.Unmarshal([]byte(raw), &task); err != nil {
		return task, err
	}
	if len(task.Executables)+len(task.Handlers) > 256 || len(task.Principals) > 16 {
		return taskPayloadDescription{}, errAssessmentLimit
	}
	return task, nil
}

// Parse argument tokens only to identify a supported file invocation. Never
// interpret shell operators, evaluate substitutions, or retain argument text.
func taskScriptPayload(executable, arguments string) (string, error) {
	name := strings.ToLower(strings.ReplaceAll(executable, `\`, "/"))
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, ".exe")
	args, err := taskArgumentTokens(arguments)
	if err != nil {
		return "", err
	}
	var candidate string
	switch name {
	case "powershell", "pwsh":
		for i, arg := range args {
			switch strings.ToLower(arg) {
			case "-command", "-c", "-encodedcommand", "-enc", "-e":
				return "", errors.ErrUnsupported
			case "-file", "-f":
				if i+1 < len(args) {
					candidate = args[i+1]
				}
				goto selected
			}
		}
	case "wscript", "cscript":
		for _, arg := range args {
			if !strings.HasPrefix(arg, "//") {
				candidate = arg
				break
			}
		}
	case "cmd":
		// Shell syntax and expansion cannot be resolved safely by this collector.
		return "", errors.ErrUnsupported
	default:
		lower := strings.ToLower(executable)
		for _, ext := range []string{".ps1", ".vbs", ".js", ".wsf", ".bat", ".cmd"} {
			if strings.HasSuffix(lower, ext) {
				return executable, nil
			}
		}
		return "", nil
	}
selected:
	if candidate == "" || strings.HasPrefix(candidate, "-") || strings.ContainsAny(candidate, "\r\n|&<>`$") {
		return "", errors.ErrUnsupported
	}
	return candidate, nil
}

func taskArgumentTokens(command string) ([]string, error) {
	if len(command) > 64<<10 {
		return nil, errAssessmentLimit
	}
	var tokens []string
	for len(command) > 0 {
		command = strings.TrimLeft(command, " \t")
		if command == "" {
			break
		}
		var token strings.Builder
		quoted := false
		for len(command) > 0 {
			ch := command[0]
			if ch == '"' {
				quoted = !quoted
				command = command[1:]
				continue
			}
			if !quoted && (ch == ' ' || ch == '\t') {
				break
			}
			if ch == '\r' || ch == '\n' {
				return nil, errors.ErrUnsupported
			}
			// Escaped quotes and shell encodings are intentionally unresolved.
			if strings.HasPrefix(command, `\"`) {
				return nil, errors.ErrUnsupported
			}
			token.WriteByte(ch)
			command = command[1:]
		}
		if quoted {
			return nil, errors.ErrUnsupported
		}
		tokens = append(tokens, token.String())
		if len(tokens) > 256 {
			return nil, errAssessmentLimit
		}
	}
	return tokens, nil
}
