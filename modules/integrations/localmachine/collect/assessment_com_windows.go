//go:build windows

package collect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/lkarlslund/adalanche/modules/basedata"
	lm "github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"golang.org/x/sys/windows"
)

func nativeCollectionResult(err error) basedata.CollectionResult {
	result := basedata.CollectionResultFromError(err)
	if errors.Is(err, windows.ERROR_TIMEOUT) {
		result.Status = basedata.CollectionTimedOut
	}
	if errors.Is(err, windows.ERROR_EVT_CHANNEL_NOT_FOUND) {
		result.Status = basedata.CollectionNotFound
	}
	if errors.Is(err, errAssessmentLimit) {
		result.ErrorCode = "collection_limit"
	}
	var com *ole.OleError
	if errors.As(err, &com) {
		code := uint32(com.Code())
		result.ErrorCode = fmt.Sprintf("hresult:%08x", code)
		switch code {
		case 0x80070005, 0x80041003:
			result.Status = basedata.CollectionAccessDenied
		case 0x80004001, 0x80040154, 0x8004100c, 0x8004100e, 0x80041010, 0x80020003, 0x80020006:
			result.Status = basedata.CollectionUnsupported
		case 0x80041002:
			result.Status = basedata.CollectionNotFound
		case 0x80043001:
			result.Status = basedata.CollectionTimedOut
		}
	}
	return result
}

func (c *assessmentCapture) operation(scope string, err error) error {
	result := nativeCollectionResult(err)
	c.failure(result)
	return c.add(map[string]any{"Kind": "coverage", "Scope": scope, "Result": result})
}

func comObject(name string) (*ole.IDispatch, error) {
	unknown, err := oleutil.CreateObject(name)
	if err != nil {
		return nil, err
	}
	defer unknown.Release()
	return unknown.QueryInterface(ole.IID_IDispatch)
}

// Copy only scalar/array values. Never recursively serialize a provider object.
func comValue(value *ole.VARIANT) (any, error) {
	if value.VT == ole.VT_EMPTY || value.VT == ole.VT_NULL {
		return nil, nil
	}
	if value.VT&ole.VT_ARRAY != 0 {
		// These are the only array types requested by our WMI projections.
		// Avoid implicit conversion of arbitrary provider objects/variants.
		switch value.VT &^ ole.VT_ARRAY {
		case ole.VT_UI1, ole.VT_I4, ole.VT_UI4, ole.VT_BSTR:
		default:
			return nil, errors.ErrUnsupported
		}
		array := value.ToArray()
		if array == nil {
			return nil, errors.ErrUnsupported
		}
		n, err := array.TotalElements(0)
		if err != nil {
			return nil, err
		}
		if n < 0 || n > 10000 {
			return nil, errAssessmentLimit
		}
		return array.ToValueArray(), nil
	}
	switch v := value.Value().(type) {
	case string:
		if len(v) > 1<<20 {
			return nil, errAssessmentLimit
		}
		return v, nil
	case bool, int8, uint8, int16, uint16, int32, uint32, int64, uint64, float32, float64, time.Time:
		return v, nil
	default:
		return nil, errors.ErrUnsupported
	}
}

func comFields(object *ole.IDispatch, names []string) (map[string]any, error) {
	record := make(map[string]any, len(names))
	for _, name := range names {
		value, err := comProperty(object, name)
		if err != nil {
			return record, err
		}
		copied, err := comValue(value)
		_ = value.Clear()
		if err != nil {
			return record, err
		}
		record[name] = copied
	}
	return record, nil
}

// WMI system properties (__CLASS, __PATH, ...) are not exposed as automation
// properties of an object; they are only reachable through SystemProperties_.
func comProperty(object *ole.IDispatch, name string) (*ole.VARIANT, error) {
	if !strings.HasPrefix(name, "__") {
		return oleutil.GetProperty(object, name)
	}
	properties, err := oleutil.GetProperty(object, "SystemProperties_")
	if err != nil {
		return nil, err
	}
	defer properties.Clear()
	if properties.ToIDispatch() == nil {
		return nil, errors.ErrUnsupported
	}
	property, err := oleutil.CallMethod(properties.ToIDispatch(), "Item", name)
	if err != nil {
		return nil, err
	}
	defer property.Clear()
	if property.ToIDispatch() == nil {
		return nil, errors.ErrUnsupported
	}
	return oleutil.GetProperty(property.ToIDispatch(), "Value")
}

func comEach(ctx context.Context, collection *ole.IDispatch, visit func(*ole.IDispatch) error) error {
	v, err := oleutil.GetProperty(collection, "_NewEnum")
	if err != nil {
		return err
	}
	defer v.Clear()
	unknown := v.ToIUnknown()
	if unknown == nil {
		return errors.ErrUnsupported
	}
	enumerator, err := unknown.IEnumVARIANT(ole.IID_IEnumVariant)
	if err != nil {
		return err
	}
	defer enumerator.Release()
	for count := 0; ; count++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, length, err := enumerator.Next(1)
		if length == 0 {
			// S_FALSE is normal end-of-enumeration, not a failed acquisition.
			var com *ole.OleError
			if errors.As(err, &com) && com.Code() == 1 {
				return nil
			}
			return err
		}
		if err != nil {
			_ = value.Clear()
			return err
		}
		if count >= 10000 {
			_ = value.Clear()
			return errAssessmentLimit
		}
		object := value.ToIDispatch()
		if object == nil {
			_ = value.Clear()
			return errors.ErrUnsupported
		}
		err = visit(object)
		_ = value.Clear()
		if err != nil {
			return err
		}
	}
}

func wmiService(namespace string) (*ole.IDispatch, error) {
	locator, err := comObject("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, err
	}
	defer locator.Release()
	args := []any{".", namespace, "", "", "", "", 128}
	if !is64Bit && os64Bit {
		// A 32-bit process otherwise reaches the 32-bit provider host, where
		// many providers are not registered. Require the native providers.
		context, err := wmiNativeContext()
		if err != nil {
			return nil, err
		}
		defer context.Release()
		args = append(args, context)
	}
	v, err := oleutil.CallMethod(locator, "ConnectServer", args...)
	if err != nil {
		return nil, err
	}
	defer v.Clear()
	service := v.ToIDispatch()
	if service == nil {
		return nil, errors.ErrUnsupported
	}
	service.AddRef()
	return service, nil
}

func wmiNativeContext() (*ole.IDispatch, error) {
	context, err := comObject("WbemScripting.SWbemNamedValueSet")
	if err != nil {
		return nil, err
	}
	for name, value := range map[string]any{"__ProviderArchitecture": int32(64), "__RequiredArchitecture": true} {
		result, err := oleutil.CallMethod(context, "Add", name, value)
		if err != nil {
			context.Release()
			return nil, err
		}
		result.Clear()
	}
	return context, nil
}

func wmiRecords(c *assessmentCapture, namespace, class string, fields []string, where string, transform func(map[string]any) error) error {
	service, err := wmiService(namespace)
	if err != nil {
		return err
	}
	defer service.Release()
	query := "SELECT " + strings.Join(fields, ",") + " FROM " + class
	if where != "" {
		query += " WHERE " + where
	}
	v, err := oleutil.CallMethod(service, "ExecQuery", query, "WQL", 48)
	if err != nil {
		return err
	}
	defer v.Clear()
	if v.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	return comEach(c.ctx, v.ToIDispatch(), func(object *ole.IDispatch) error {
		record, err := comFields(object, fields)
		if err != nil {
			return err
		}
		if transform != nil {
			return transform(record)
		}
		return c.add(record)
	})
}

func collectSMBConfiguration(c *assessmentCapture, class string, fields []string) error {
	service, err := wmiService(`root\Microsoft\Windows\SMB`)
	if err != nil {
		return err
	}
	defer service.Release()
	v, err := oleutil.CallMethod(service, "Get", class)
	if err != nil {
		return err
	}
	defer v.Clear()
	if v.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	output, err := oleutil.CallMethod(v.ToIDispatch(), "ExecMethod_", "GetConfiguration")
	if err != nil {
		return err
	}
	defer output.Clear()
	if output.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	status, err := oleutil.GetProperty(output.ToIDispatch(), "ReturnValue")
	if err != nil {
		return err
	}
	code := status.Val
	_ = status.Clear()
	if code != 0 {
		return syscall.Errno(code)
	}
	config, err := oleutil.GetProperty(output.ToIDispatch(), "Output")
	if err != nil {
		return err
	}
	defer config.Clear()
	if config.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	record, err := comFields(config.ToIDispatch(), fields)
	if err != nil {
		return err
	}
	return c.add(record)
}

// Assessment categories run in parallel, each on its own worker. COM
// categories get a thread joined to the multithreaded apartment.
func init() {
	comJobs := map[string]func(*assessmentCapture) error{
		"smb-client": func(c *assessmentCapture) error {
			return collectSMBConfiguration(c, "MSFT_SmbClientConfiguration", []string{"RequireSecuritySignature", "EnableInsecureGuestLogons", "EnableSecuritySignature"})
		},
		"smb-server": func(c *assessmentCapture) error {
			return collectSMBConfiguration(c, "MSFT_SmbServerConfiguration", []string{"RequireSecuritySignature", "EnableSMB1Protocol", "EnableSMB2Protocol", "EncryptData", "RejectUnencryptedAccess"})
		},
		"credential-protection": func(c *assessmentCapture) error {
			return wmiRecords(c, `root\Microsoft\Windows\DeviceGuard`, "Win32_DeviceGuard", []string{"VirtualizationBasedSecurityStatus", "SecurityServicesConfigured", "SecurityServicesRunning", "AvailableSecurityProperties", "RequiredSecurityProperties"}, "", nil)
		},
		"service-runtime": func(c *assessmentCapture) error {
			return wmiRecords(c, `root\cimv2`, "Win32_Service", []string{"Name", "State", "StartMode", "StartName", "ProcessId"}, "", nil)
		},
		"listeners": func(c *assessmentCapture) error {
			return wmiRecords(c, `root\StandardCimv2`, "MSFT_NetTCPConnection", []string{"LocalAddress", "LocalPort", "OwningProcess"}, "State = 2", nil)
		},
		"network-profiles": func(c *assessmentCapture) error {
			return wmiRecords(c, `root\StandardCimv2`, "MSFT_NetConnectionProfile", []string{"InterfaceIndex", "NetworkCategory", "IPv4Connectivity", "IPv6Connectivity"}, "", nil)
		},
		"firewall-profiles":    collectFirewallProfiles,
		"firewall-rules":       collectFirewallRules,
		"task-security":        collectNativeTaskSecurity,
		"startup":              collectNativeStartup,
		"event-subscriptions":  collectNativeEventSubscriptions,
		"event-consumers":      collectNativeEventConsumers,
		"remote-endpoints":     func(c *assessmentCapture) error { return collectWSMan(c, "plugin") },
		"remote-listeners":     func(c *assessmentCapture) error { return collectWSMan(c, "listener") },
		"policy-provenance":    collectPolicyProvenance,
		"task-payloads":        collectTaskPayloads,
		"firewall-filters":     collectFirewallFilters,
		"remote-configuration": collectRemoteConfiguration,
		"wmi-security":         collectWMISecurity,
		"smb-shares": func(c *assessmentCapture) error {
			return wmiRecords(c, `root\Microsoft\Windows\SMB`, "MSFT_SmbShare", []string{"Name", "ScopeName", "Path", "EncryptData", "FolderEnumerationMode", "ContinuouslyAvailable"}, "", nil)
		},
		"smb-connections": collectSMBConnections,
	}
	nativeJobs := map[string]func(*assessmentCapture, *lm.Info) error{
		"credential-locations":       func(c *assessmentCapture, _ *lm.Info) error { return collectCredentialLocations(c) },
		"password-management-policy": collectPasswordPolicy,
		"user-installer-policy":      func(c *assessmentCapture, _ *lm.Info) error { return collectUserInstallerPolicy(c) },
		"password-management-events": func(c *assessmentCapture, _ *lm.Info) error { return collectPasswordEvents(c) },
		"lsa-protection-runtime":     func(c *assessmentCapture, _ *lm.Info) error { return collectLSAProtectionEvents(c) },
		"machine-certificates":       func(c *assessmentCapture, _ *lm.Info) error { return collectMachineCertificates(c) },
		"service-payloads":           collectServicePayloads,
		"current-sessions":           func(c *assessmentCapture, _ *lm.Info) error { return collectCurrentSessions(c) },
		"process-identities":         func(c *assessmentCapture, _ *lm.Info) error { return collectProcessIdentities(c) },
		"authentication-policy":      func(c *assessmentCapture, _ *lm.Info) error { return collectAuthenticationPolicy(c) },
		"dcom-security":              func(c *assessmentCapture, _ *lm.Info) error { return collectDCOMSecurity(c) },
	}
	for _, name := range assessmentCategories {
		thread := ThreadAny
		collect := nativeJobs[name]
		if job, ok := comJobs[name]; ok {
			thread = ThreadCOM
			collect = func(c *assessmentCapture, _ *lm.Info) error { return job(c) }
		}
		if collect == nil {
			panic("assessment category without a collector: " + name)
		}
		RegisterCollector(Collector{
			Name:     name,
			Category: name,
			Stage:    StageAssessment,
			Thread:   thread,
			Collect: func(env *Env) func(*Result) {
				capture := runAssessmentCategory(env, func(c *assessmentCapture) error {
					if thread == ThreadCOM && env.COMError != nil {
						return env.COMError
					}
					return collect(c, env.Info)
				})
				return func(r *Result) { r.Assessment.Categories[name] = capture }
			},
		})
	}
}

func runAssessmentCategory(env *Env, collect func(*assessmentCapture) error) lm.AssessmentCapture {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	capture := newAssessmentCapture(ctx)
	capture.budget = env.budget
	err := collect(capture)
	if err == nil {
		err = ctx.Err()
	}
	capture.failure(nativeCollectionResult(err))
	capture.data.Truncated = capture.data.Truncated || errors.Is(err, errAssessmentLimit) || errors.Is(err, context.DeadlineExceeded)
	capture.data.Completed = time.Now().UTC()
	return capture.data
}
