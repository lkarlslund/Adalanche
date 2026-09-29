//go:build windows

package collect

import (
	"context"
	"encoding/json"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unsafe"

	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"golang.org/x/sys/windows"
)

// Derived checks read every merged inventory and assessment record, so they
// run after the assessment stage. They work on copies of the services and
// tasks they update, and publish them in one merge.
func init() {
	RegisterCollector(Collector{
		Name:  "assessment-derived",
		Stage: StageDerived,
		Collect: func(env *Env) func(*Result) {
			info := *env.Info
			info.Services = slices.Clone(env.Info.Services)
			info.Tasks = slices.Clone(env.Info.Tasks)
			info.CollectionResults = env.Outcomes
			a := lm.Assessment{Categories: maps.Clone(env.Assessment.Categories)}
			collectAssessment(&info, &a)
			return func(r *Result) {
				r.Info.Services = info.Services
				r.Info.Tasks = info.Tasks
				r.Assessment.Paths = a.Paths
				for _, name := range []string{"path-security", "service-restrictions"} {
					r.Assessment.Categories[name] = a.Categories[name]
				}
			}
		},
	})
}

func collectAssessment(info *lm.Info, a *lm.Assessment) {
	if info.CollectionResults == nil {
		info.CollectionResults = basedata.CollectionResults{}
	}
	applyTaskSecurity(info, a.Categories["task-security"])
	seen := map[string]lm.PathSecurity{}
	pathResult := basedata.CollectionResultFromError(nil)
	pathBytes := 0
	pathStarted := time.Now().UTC()
	pathDeadline := time.Now().Add(2 * time.Minute)
	addPath := func(path, purpose, subject string, configured ...string) {
		if !AssessmentEnabled("path-security") {
			return
		}
		if time.Now().After(pathDeadline) {
			pathResult = basedata.CollectionResult{Status: basedata.CollectionTimedOut}
			return
		}
		if path == "" || path == "." {
			return
		}
		key := strings.ToLower(filepath.Clean(path))
		item, ok := seen[key]
		if !ok {
			if len(seen) >= 4096 {
				pathResult = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "path_limit"}
				return
			}
			item = inspectAssessmentPath(path)
			seen[key] = item
		}
		item.ConfiguredPath = path
		if len(configured) > 0 && configured[0] != "" {
			item.ConfiguredPath = configured[0]
		}
		// Remote, unexpanded and reparse paths are deliberately not inspected.
		// Each item records that; it does not make the category incomplete.
		if item.Result.Status != basedata.CollectionCollected && item.Result.Status != basedata.CollectionUnsupported && pathResult.Status == basedata.CollectionCollected {
			pathResult = item.Result
		}
		if len(a.Paths) >= 8192 {
			pathResult = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "reference_limit"}
			return
		}
		item.Purpose, item.Subject = purpose, subject
		// Bound the serialized references too: the same ACL may be referenced by
		// several payloads even though its native read was deduplicated.
		encoded, err := json.Marshal(item)
		if err != nil || len(encoded) > (4<<20)-pathBytes {
			pathResult = basedata.CollectionResult{Status: basedata.CollectionFailed, ErrorCode: "path_bytes_limit"}
			return
		}
		pathBytes += len(encoded)
		a.Paths = append(a.Paths, item)
	}
	for i := range info.Services {
		s := &info.Services[i]
		addPath(s.ImageExecutable, "service-payload", s.Name, startupExecutable(s.ImagePath))
		addPath(filepath.Dir(s.ImageExecutable), "service-parent", s.Name)
		for _, candidate := range servicePathCandidates(s.ImagePath) {
			addPath(candidate, "service-candidate", s.Name)
			addPath(filepath.Dir(candidate), "service-candidate-parent", s.Name)
		}
	}
	for _, t := range info.Tasks {
		for _, action := range t.Definition.Actions {
			if action.Path != "" {
				addPath(action.Path, "task-payload", t.Path)
				addPath(filepath.Dir(action.Path), "task-parent", t.Path)
			}
		}
	}
	for _, name := range []string{"startup", "event-consumers", "machine-certificates", "credential-locations", "service-payloads", "task-payloads"} {
		for _, raw := range a.Categories[name].Records {
			var item struct{ Name, Executable, ScriptFile, KeyPath, Path, UserSID, Thumbprint, Payload, ConfiguredPayload string }
			if json.Unmarshal(raw, &item) != nil {
				continue
			}
			if item.Name == "" {
				item.Name = item.UserSID
			}
			if item.Name == "" {
				item.Name = item.Thumbprint
			}
			paths := []string{item.Executable, item.ScriptFile, item.KeyPath, item.Path, item.Payload}
			if name == "task-payloads" || name == "service-payloads" {
				paths = []string{item.Payload}
			}
			for _, path := range paths {
				if path != "" {
					addPath(path, name, item.Name, item.ConfiguredPayload)
					if name == "startup" || name == "event-consumers" || name == "task-payloads" || name == "service-payloads" {
						addPath(filepath.Dir(path), name+"-parent", item.Name)
					}
				}
			}
		}
	}
	a.Categories["path-security"] = lm.AssessmentCapture{Started: pathStarted, Completed: time.Now().UTC(), Scope: "local-payload-paths-and-parents", Result: pathResult, Truncated: pathResult.Status == basedata.CollectionTimedOut || strings.HasSuffix(pathResult.ErrorCode, "limit")}
	if !AssessmentEnabled("path-security") {
		a.Categories["path-security"] = lm.AssessmentCapture{Result: basedata.CollectionResult{Status: basedata.CollectionNotRequested}}
	}
	if AssessmentEnabled("service-restrictions") {
		collectServiceSecurity(info, a)
	} else {
		a.Categories["service-restrictions"] = lm.AssessmentCapture{Result: basedata.CollectionResult{Status: basedata.CollectionNotRequested}}
	}
}

func collectServiceSecurity(info *lm.Info, assessment *lm.Assessment) {
	if info.CollectionResults == nil {
		info.CollectionResults = basedata.CollectionResults{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	capture := newAssessmentCapture(ctx)
	capture.limit = 2 << 20
	capture.data.Scope = "local-service-api-security-and-sid-type"
	defer func() {
		capture.failure(nativeCollectionResult(ctx.Err()))
		capture.data.Completed = time.Now().UTC()
		assessment.Categories["service-restrictions"] = capture.data
	}()
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		capture.failure(nativeCollectionResult(err))
		info.CollectionResults["services/api-open"] = basedata.CollectionResultFromError(err)
		return
	}
	defer windows.CloseServiceHandle(manager)
	info.CollectionResults["services/api-open"] = basedata.CollectionResultFromError(nil)
	for i := range info.Services {
		if ctx.Err() != nil {
			return
		}
		if i >= 10000 {
			capture.failure(nativeCollectionResult(errAssessmentLimit))
			break
		}
		s := &info.Services[i]
		name, err := windows.UTF16PtrFromString(s.Name)
		if err != nil {
			continue
		}
		h, err := windows.OpenService(manager, name, windows.READ_CONTROL|windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			capture.failure(nativeCollectionResult(err))
			info.CollectionResults["services/api-security/"+s.Name] = basedata.CollectionResultFromError(err)
			continue
		}
		sd, err := windows.GetSecurityInfo(h, windows.SE_SERVICE, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		info.CollectionResults["services/api-security/"+s.Name] = basedata.CollectionResultFromError(err)
		capture.failure(nativeCollectionResult(err))
		if err == nil {
			s.SecurityDescriptor = append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sd)), int(sd.Length()))...)
			info.CollectionResults["services/security/"+s.Name] = basedata.CollectionResultFromError(nil)
		}
		var sidType uint32
		var required uint32
		err = windows.QueryServiceConfig2(h, windows.SERVICE_CONFIG_SERVICE_SID_INFO, (*byte)(unsafe.Pointer(&sidType)), 4, &required)
		capture.failure(nativeCollectionResult(err))
		record := struct {
			Name    string
			SIDType uint32
			Result  basedata.CollectionResult
		}{s.Name, sidType, basedata.CollectionResultFromError(err)}
		windows.CloseServiceHandle(h)
		if err := capture.add(record); err != nil {
			capture.failure(nativeCollectionResult(err))
			return
		}
	}
}
