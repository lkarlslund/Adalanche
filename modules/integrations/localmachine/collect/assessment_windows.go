//go:build windows

package collect

import (
	"bufio"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/sys/windows"
)

//go:embed assessment.ps1
var assessmentScript string

var assessmentCategories = []string{"smb-client", "smb-server", "credential-protection", "lsa-protection-runtime", "service-runtime", "task-security", "listeners", "firewall-profiles", "network-profiles", "firewall-rules", "remote-endpoints", "remote-listeners", "startup", "event-subscriptions", "event-consumers", "machine-certificates", "credential-locations", "password-management-policy", "password-management-events", "user-installer-policy"}

func collectAssessment(info *lm.Info) {
	a := lm.Assessment{Version: lm.AssessmentVersion, Captured: time.Now().UTC(), Categories: map[string]lm.AssessmentCapture{}}
	for _, name := range assessmentCategories {
		a.Categories[name] = lm.AssessmentCapture{Result: basedata.CollectionResult{Status: basedata.CollectionNotRequested}}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	encoded := utf16.Encode([]rune(assessmentScript))
	bytes := make([]byte, len(encoded)*2)
	for i, v := range encoded {
		binary.LittleEndian.PutUint16(bytes[i*2:], v)
	}
	command := exec.CommandContext(ctx, "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(bytes))
	stdout, err := command.StdoutPipe()
	if err == nil {
		err = command.Start()
	}
	if err == nil {
		stopClose := context.AfterFunc(ctx, func() { _ = stdout.Close() })
		defer stopClose()
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 4096), 8<<20)
		total := 0
		for scanner.Scan() {
			total += len(scanner.Bytes())
			if total > 24<<20 {
				err = errors.New("assessment limit")
				_ = command.Process.Kill()
				break
			}
			var line struct {
				Name    string               `json:"name"`
				Capture lm.AssessmentCapture `json:"capture"`
			}
			if json.Unmarshal(scanner.Bytes(), &line) == nil {
				if _, known := a.Categories[line.Name]; known {
					a.Categories[line.Name] = line.Capture
				}
			}
		}
		if scanErr := scanner.Err(); scanErr != nil {
			err = scanErr
			_ = command.Process.Kill()
		}
		if waitErr := command.Wait(); err == nil {
			err = waitErr
		}
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	for name, capture := range a.Categories {
		if capture.Result.Status == basedata.CollectionNotRequested {
			if err == nil {
				err = errors.New("missing category")
			}
			capture.Result = basedata.CollectionResultFromError(err)
			a.Categories[name] = capture
		}
	}
	if info.CollectionResults == nil {
		info.CollectionResults = basedata.CollectionResults{}
	}
	applyTaskSecurity(info, a.Categories["task-security"])
	seen := map[string]lm.PathSecurity{}
	pathResult := basedata.CollectionResultFromError(nil)
	pathBytes := 0
	pathDeadline := time.Now().Add(2 * time.Minute)
	addPath := func(path, purpose, subject string) {
		if time.Now().After(pathDeadline) {
			pathResult = basedata.CollectionResult{Status: basedata.CollectionTimedOut}
			return
		}
		if path == "" || path == "." {
			return
		}
		path = resolvepath(path)
		if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) {
			pathResult = basedata.CollectionResult{Status: basedata.CollectionUnsupported, ErrorCode: "non_local_path"}
			return
		} // Do not explicitly query UNC paths.
		key := strings.ToLower(filepath.Clean(path))
		item, ok := seen[key]
		if !ok {
			if len(seen) >= 4096 {
				pathResult = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "path_limit"}
				return
			}
			owner, dacl, err := windowssecurity.GetOwnerAndDACL(path, windowssecurity.SE_FILE_OBJECT)
			pathBytes += len(dacl) + len(path)
			if pathBytes > 4<<20 {
				pathResult = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "path_bytes_limit"}
				return
			}
			item = lm.PathSecurity{Path: path, Result: basedata.CollectionResultFromError(err)}
			if err == nil {
				item.Owner = owner.String()
				item.DACL = dacl
			}
			seen[key] = item
		}
		if len(a.Paths) >= 8192 {
			pathResult = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "reference_limit"}
			return
		}
		item.Purpose, item.Subject = purpose, subject
		a.Paths = append(a.Paths, item)
	}
	for i := range info.Services {
		s := &info.Services[i]
		addPath(filepath.Dir(resolvepath(s.ImageExecutable)), "service-parent", s.Name)
		for _, candidate := range servicePathCandidates(s.ImagePath) {
			addPath(candidate, "service-candidate", s.Name)
			addPath(filepath.Dir(candidate), "service-candidate-parent", s.Name)
		}
	}
	for _, t := range info.Tasks {
		for _, action := range t.Definition.Actions {
			if action.Path != "" {
				addPath(filepath.Dir(resolvepath(action.Path)), "task-parent", t.Path)
			}
		}
	}
	for _, name := range []string{"startup", "event-consumers", "machine-certificates", "credential-locations"} {
		for _, raw := range a.Categories[name].Records {
			var item struct{ Name, Executable, ScriptFile, KeyPath, Path, UserSID, Thumbprint string }
			if json.Unmarshal(raw, &item) != nil {
				continue
			}
			if item.Name == "" {
				item.Name = item.UserSID
			}
			if item.Name == "" {
				item.Name = item.Thumbprint
			}
			for _, path := range []string{item.Executable, item.ScriptFile, item.KeyPath, item.Path} {
				if path != "" {
					addPath(path, name, item.Name)
					if name == "startup" || name == "event-consumers" {
						addPath(filepath.Dir(resolvepath(path)), name+"-parent", item.Name)
					}
				}
			}
		}
	}
	a.Categories["path-security"] = lm.AssessmentCapture{Result: pathResult}
	collectServiceSecurity(info, &a)
	if raw, err := json.Marshal(a); err == nil {
		info.AssessmentData = string(raw)
	}
}

func collectServiceSecurity(info *lm.Info, assessment *lm.Assessment) {
	if info.CollectionResults == nil {
		info.CollectionResults = basedata.CollectionResults{}
	}
	capture := lm.AssessmentCapture{Result: basedata.CollectionResultFromError(nil)}
	defer func() { assessment.Categories["service-restrictions"] = capture }()
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		capture.Result = basedata.CollectionResultFromError(err)
		info.CollectionResults["services/api-open"] = basedata.CollectionResultFromError(err)
		return
	}
	defer windows.CloseServiceHandle(manager)
	info.CollectionResults["services/api-open"] = basedata.CollectionResultFromError(nil)
	for i := range info.Services {
		if i >= 10000 {
			capture.Result = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "service_limit"}
			break
		}
		s := &info.Services[i]
		name, err := windows.UTF16PtrFromString(s.Name)
		if err != nil {
			continue
		}
		h, err := windows.OpenService(manager, name, windows.READ_CONTROL|windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			capture.Result = basedata.CollectionResultFromError(err)
			info.CollectionResults["services/api-security/"+s.Name] = basedata.CollectionResultFromError(err)
			continue
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		info.CollectionResults["services/api-security/"+s.Name] = basedata.CollectionResultFromError(err)
		if err == nil {
			s.SecurityDescriptor = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length()))...)
			info.CollectionResults["services/security/"+s.Name] = basedata.CollectionResultFromError(nil)
		}
		var sidType uint32
		var required uint32
		err = windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType)), 4, &required)
		record, marshalErr := json.Marshal(struct {
			Name    string
			SIDType uint32
			Result  basedata.CollectionResult
		}{s.Name, sidType, basedata.CollectionResultFromError(err)})
		if marshalErr == nil {
			capture.Records = append(capture.Records, record)
		}
		windows.CloseServiceHandle(h)
	}
}
