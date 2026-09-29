//go:build windows

package collect

import (
	"errors"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func collectTaskPayloads(c *assessmentCapture) error {
	scheduler, err := comObject("Schedule.Service")
	if err != nil {
		return err
	}
	defer scheduler.Release()
	v, err := oleutil.CallMethod(scheduler, "Connect")
	if err != nil {
		return err
	}
	_ = v.Clear()
	queue := []string{`\`}
	for visited := 0; len(queue) > 0; visited++ {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if visited >= 4096 {
			return errAssessmentLimit
		}
		path := queue[0]
		queue = queue[1:]
		err := func() error {
			folder, err := oleutil.CallMethod(scheduler, "GetFolder", path)
			if err != nil {
				return err
			}
			defer folder.Clear()
			object := folder.ToIDispatch()
			if object == nil {
				return errors.ErrUnsupported
			}
			sd, sdErr := oleutil.CallMethod(object, "GetSecurityDescriptor", 4)
			r := map[string]any{"Kind": "task-folder", "Path": path, "Result": nativeCollectionResult(sdErr)}
			if sdErr == nil {
				r["SDDL"] = sd.ToString()
				_ = sd.Clear()
			} else {
				c.failure(nativeCollectionResult(sdErr))
			}
			if err := c.add(r); err != nil {
				return err
			}
			tasks, err := oleutil.CallMethod(object, "GetTasks", 1)
			if err != nil {
				return err
			}
			defer tasks.Clear()
			if tasks.ToIDispatch() == nil {
				return errors.ErrUnsupported
			}
			err = comEach(c.ctx, tasks.ToIDispatch(), func(task *ole.IDispatch) error {
				r, err := comFields(task, []string{"Path", "Enabled"})
				if err != nil {
					return err
				}
				name, _ := r["Path"].(string)
				xmlValue, err := oleutil.GetProperty(task, "Xml")
				if err != nil {
					return err
				}
				description, parseErr := parseTaskPayloads(xmlValue.ToString())
				_ = xmlValue.Clear()
				r["Kind"], r["Result"] = "task-principal", nativeCollectionResult(parseErr)
				if parseErr != nil {
					c.failure(nativeCollectionResult(parseErr))
					return c.add(r)
				}
				principalSID := ""
				for _, principal := range description.Principals {
					identity := principal.UserID
					if identity == "" {
						identity = principal.GroupID
					}
					sid, sidErr := resolvePrincipalSID(identity)
					r["UserID"], r["GroupID"], r["LogonType"], r["RunLevel"] = principal.UserID, principal.GroupID, principal.LogonType, principal.RunLevel
					r["SID"], r["SIDResult"] = sid, nativeCollectionResult(sidErr)
					if principal.UserID != "" && sidErr == nil {
						principalSID = sid
					}
					if err := c.add(r); err != nil {
						return err
					}
				}
				for i, action := range description.Executables {
					payload, payloadErr := taskScriptPayload(action.Command, action.Arguments)
					configuredPayload := payload
					if payload != "" {
						payload, payloadErr = localPayloadPath(payload, action.WorkingDirectory)
					}
					if err := c.add(map[string]any{"Name": name, "Kind": "task-script", "ActionIndex": i, "Payload": payload, "ConfiguredPayload": configuredPayload, "Result": nativeCollectionResult(payloadErr), "ReferenceFound": payload != ""}); err != nil {
						return err
					}
				}
				for i, handler := range description.Handlers {
					if err := collectTaskCOMHandler(c, name, i, handler.ClassID, principalSID); err != nil {
						return err
					}
				}
				return nil
			})
			if err != nil {
				return err
			}
			children, err := oleutil.CallMethod(object, "GetFolders", 0)
			if err != nil {
				return err
			}
			defer children.Clear()
			if children.ToIDispatch() == nil {
				return errors.ErrUnsupported
			}
			return comEach(c.ctx, children.ToIDispatch(), func(child *ole.IDispatch) error {
				r, err := comFields(child, []string{"Path"})
				if err != nil {
					return err
				}
				p, ok := r["Path"].(string)
				if !ok {
					return errors.ErrUnsupported
				}
				if len(queue)+visited >= 4096 {
					return errAssessmentLimit
				}
				queue = append(queue, p)
				return nil
			})
		}()
		if err != nil {
			c.failure(nativeCollectionResult(err))
			if err := c.operation("task-folder:"+path, err); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolvePrincipalSID(identity string) (string, error) {
	if identity == "" {
		return "", errors.ErrUnsupported
	}
	if sid, err := windows.StringToSid(identity); err == nil {
		return sid.String(), nil
	}
	sid, _, _, err := windows.LookupSID("", identity)
	if err != nil {
		return "", err
	}
	return sid.String(), nil
}

func localPayloadPath(path, workingDirectory string) (string, error) {
	path = resolvepath(strings.Trim(path, `"`))
	if !filepath.IsAbs(path) && workingDirectory != "" {
		path = filepath.Join(resolvepath(workingDirectory), path)
	}
	if !filepath.IsAbs(path) || strings.HasPrefix(path, `\\`) || strings.Contains(path, "%") {
		return "", errors.ErrUnsupported
	}
	return filepath.Clean(path), nil
}

func collectTaskCOMHandler(c *assessmentCapture, task string, index int, class, sid string) error {
	guid, err := windows.GUIDFromString(class)
	if err != nil {
		return c.add(map[string]any{"Name": task, "ClassID": class, "Result": nativeCollectionResult(errors.ErrUnsupported)})
	}
	class = guid.String()
	type scope struct {
		root          registry.Key
		prefix, label string
	}
	scopes := []scope{{registry.LOCAL_MACHINE, `SOFTWARE\Classes\CLSID\`, "machine"}}
	if sid != "" {
		scopes = append(scopes, scope{registry.USERS, sid + `\Software\Classes\CLSID\`, "loaded-task-user"})
	}
	for _, scope := range scopes {
		for _, view := range []uint32{registry.WOW64_64KEY, registry.WOW64_32KEY} {
			for _, server := range []string{"InprocServer32", "LocalServer32"} {
				path := scope.prefix + class + `\` + server
				r := map[string]any{"Name": task, "Kind": "task-com-handler", "ActionIndex": index, "ClassID": class, "Registration": path, "Scope": scope.label, "RegistryView": view, "ServerKind": server, "EffectiveRegistrationKnown": false}
				key, err := registry.OpenKey(scope.root, path, registry.QUERY_VALUE|view)
				if err == nil {
					value, _, valueErr := key.GetStringValue("")
					key.Close()
					err = valueErr
					if err == nil {
						if server == "LocalServer32" {
							value = startupExecutable(value)
							if value == "" {
								err = errors.ErrUnsupported
							}
						}
						if err == nil {
							r["ConfiguredPayload"] = value
							r["Payload"], err = registryPayloadPath(value, view)
						}
					}
				}
				r["Result"] = nativeCollectionResult(err)
				// Open separately so denied READ_CONTROL does not hide a readable
				// payload. Handle-based security preserves the requested registry view.
				aclKey, aclErr := registry.OpenKey(scope.root, path, windows.READ_CONTROL|view)
				if aclErr == nil {
					sd, readErr := windows.GetSecurityInfo(windows.Handle(aclKey), windows.SE_REGISTRY_KEY, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
					aclKey.Close()
					aclErr = readErr
					if readErr == nil {
						r["RegistrySDDL"] = sd.String()
					}
				}
				r["RegistrySecurityResult"] = nativeCollectionResult(aclErr)
				if err := c.add(r); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func registryPayloadPath(value string, view uint32) (string, error) {
	if view == registry.WOW64_32KEY && os64Bit {
		// A 32-bit registration uses the 32-bit environment and system directory,
		// regardless of the collector's own architecture.
		value = programFilesVariable.ReplaceAllString(value, "%ProgramFiles(x86)%")
		expanded, err := registry.ExpandString(value)
		if err != nil {
			return "", err
		}
		value = expanded
		if strings.EqualFold(value, win32folder) || strings.HasPrefix(strings.ToLower(value), win32folder+`\`) {
			proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemWow64DirectoryW")
			if err := proc.Find(); err != nil {
				return "", errors.ErrUnsupported
			}
			buffer := make([]uint16, 32768)
			n, _, err := proc.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)))
			if n == 0 {
				return "", err
			}
			if n >= uintptr(len(buffer)) {
				return "", errAssessmentLimit
			}
			value = windows.UTF16ToString(buffer[:n]) + value[len(win32folder):]
		}
	}
	return localPayloadPath(value, "")
}
