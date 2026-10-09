//go:build windows

package collect

import (
	"errors"
	"runtime"
	"unsafe"

	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type serviceTrigger struct {
	Type, Action uint32
	Subtype      *windows.GUID
	DataCount    uint32
	Data         unsafe.Pointer
}
type serviceTriggers struct {
	Count    uint32
	Triggers *serviceTrigger
	Reserved unsafe.Pointer
}

func serviceConfig(handle windows.Handle, level uint32) ([]byte, error) {
	var size uint32
	err := windows.QueryServiceConfig2(handle, level, nil, 0, &size)
	if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
		return nil, err
	}
	if size == 0 || size > 1<<20 {
		return nil, errAssessmentLimit
	}
	buffer := make([]byte, size)
	err = windows.QueryServiceConfig2(handle, level, &buffer[0], size, &size)
	return buffer, err
}

func collectServicePayloads(c *assessmentCapture, info *lm.Info) error {
	manager, managerErr := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if managerErr == nil {
		defer windows.CloseServiceHandle(manager)
	}
	c.failure(nativeCollectionResult(managerErr))
	for _, service := range info.Services {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		path := `SYSTEM\CurrentControlSet\Services\` + service.Name + `\Parameters`
		r, err := registryAssessment(c, registry.LOCAL_MACHINE, path, nil)
		if err != nil {
			return err
		}
		r["Name"], r["Kind"] = service.Name, "service-dll"
		registryStrings(c, registry.LOCAL_MACHINE, path, r, []string{"ServiceDll", "ServiceMain"}, nil)
		if dll, ok := r["ServiceDll"].(string); ok {
			r["Payload"] = dll
		}
		owner, dacl, aclErr := windowssecurity.GetOwnerAndDACL(`MACHINE\`+path, windowssecurity.SE_REGISTRY_KEY)
		r["RegistrySecurityResult"] = nativeCollectionResult(aclErr)
		if aclErr == nil {
			r["RegistryOwner"], r["RegistryDACL"] = owner.String(), dacl
		}
		if err := c.add(r); err != nil {
			return err
		}
		if managerErr != nil {
			continue
		}
		name, err := windows.UTF16PtrFromString(service.Name)
		if err != nil {
			return err
		}
		handle, err := windows.OpenService(manager, name, windows.SERVICE_QUERY_CONFIG)
		if err != nil {
			c.failure(nativeCollectionResult(err))
			if err := c.add(map[string]any{"Name": service.Name, "Kind": "service-config", "Result": nativeCollectionResult(err)}); err != nil {
				return err
			}
			continue
		}
		err = func() error {
			defer windows.CloseServiceHandle(handle)
			for _, level := range []uint32{2, 4, 8, 12} { // Failure actions/flag, triggers, launch protection.
				buffer, err := serviceConfig(handle, level)
				r := map[string]any{"Name": service.Name, "ConfigLevel": level, "Result": nativeCollectionResult(err)}
				if err == nil && len(buffer) > 0 {
					switch level {
					case 2:
						if len(buffer) < int(unsafe.Sizeof(windows.SERVICE_FAILURE_ACTIONS{})) {
							return errors.ErrUnsupported
						}
						f := (*windows.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&buffer[0]))
						r["Kind"], r["ResetPeriod"] = "service-failure-actions", f.ResetPeriod
						command := windows.UTF16PtrToString(f.Command)
						r["Payload"] = startupExecutable(command)
						r["CommandPresent"], r["PayloadResolved"] = command != "", r["Payload"] != ""
						if f.ActionsCount > 1024 {
							return errAssessmentLimit
						}
						if f.ActionsCount > 0 && f.Actions != nil {
							r["Actions"] = append([]windows.SC_ACTION(nil), unsafe.Slice(f.Actions, f.ActionsCount)...)
						}
					case 8:
						if len(buffer) < int(unsafe.Sizeof(serviceTriggers{})) {
							return errors.ErrUnsupported
						}
						triggers := (*serviceTriggers)(unsafe.Pointer(&buffer[0]))
						if triggers.Count > 1024 {
							return errAssessmentLimit
						}
						var items []map[string]any
						if triggers.Triggers != nil {
							for _, trigger := range unsafe.Slice(triggers.Triggers, triggers.Count) {
								item := map[string]any{"Type": trigger.Type, "Action": trigger.Action, "DataItemCount": trigger.DataCount}
								if trigger.Subtype != nil {
									item["Subtype"] = trigger.Subtype.String()
								}
								items = append(items, item)
							}
						}
						r["Kind"], r["Triggers"] = "service-triggers", items
					default:
						if len(buffer) < 4 {
							return errors.ErrUnsupported
						}
						r["Value"] = *(*uint32)(unsafe.Pointer(&buffer[0]))
					}
				} else {
					c.failure(nativeCollectionResult(err))
				}
				runtime.KeepAlive(buffer)
				if err := c.add(r); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}
