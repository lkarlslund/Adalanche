//go:build windows

package collect

import (
	"errors"
	"io"
	"strings"
	"syscall"

	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows/registry"
)

func collectFirewallFilters(c *assessmentCapture) error {
	c.data.Scope = "native-provider-reported-policy;not-a-reachability-verdict"
	for _, q := range []struct {
		class  string
		fields []string
	}{
		{"MSFT_NetFirewallRule", []string{"InstanceID", "DisplayName", "Enabled", "Direction", "Action", "Profiles", "PolicyStoreSource", "PolicyStoreSourceType", "PrimaryStatus", "StatusCode"}},
		{"MSFT_NetApplicationFilter", []string{"InstanceID", "AppPath", "Package"}},
		{"MSFT_NetServiceFilter", []string{"InstanceID", "ServiceName"}},
		{"MSFT_NetInterfaceFilter", []string{"InstanceID", "InterfaceAlias"}},
		{"MSFT_NetInterfaceTypeFilter", []string{"InstanceID", "InterfaceType"}},
		{"MSFT_NetProtocolPortFilter", []string{"InstanceID", "Protocol", "LocalPort", "RemotePort", "IcmpType", "DynamicTransport"}},
		{"MSFT_NetAddressFilter", []string{"InstanceID", "LocalAddress", "RemoteAddress"}},
		{"MSFT_NetNetworkLayerSecurityFilter", []string{"InstanceID", "Authentication", "Encryption", "OverrideBlockRules", "LocalUsers", "RemoteUsers", "RemoteMachines"}},
		{"MSFT_NetFirewallRuleFilterByAddress", []string{"GroupComponent", "PartComponent"}},
		{"MSFT_NetFirewallRuleFilterByApplication", []string{"GroupComponent", "PartComponent"}},
		{"MSFT_NetFirewallRuleFilterByInterface", []string{"GroupComponent", "PartComponent"}},
		{"MSFT_NetFirewallRuleFilterByInterfaceType", []string{"GroupComponent", "PartComponent"}},
		{"MSFT_NetFirewallRuleFilterByProtocolPort", []string{"GroupComponent", "PartComponent"}},
		{"MSFT_NetFirewallRuleFilterBySecurity", []string{"GroupComponent", "PartComponent"}},
		{"MSFT_NetFirewallRuleFilterByService", []string{"GroupComponent", "PartComponent"}},
	} {
		fields := append([]string{"__PATH", "__RELPATH"}, q.fields...)
		err := wmiRecords(c, `root\StandardCimv2`, q.class, fields, "", func(r map[string]any) error {
			r["Class"], r["PolicyScope"], r["EffectivePolicyKnown"] = q.class, "provider-default", false
			return c.add(r)
		})
		c.failure(nativeCollectionResult(err))
		if err := c.operation(q.class, err); err != nil {
			return err
		}
	}
	return nil
}

func collectRemoteConfiguration(c *assessmentCapture) error {
	client, err := comObject("WSMan.Automation")
	if err != nil {
		return err
	}
	defer client.Release()
	session, err := oleutil.CallMethod(client, "CreateSession", "", 0)
	if err != nil {
		return err
	}
	defer session.Clear()
	if session.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	v, err := oleutil.PutProperty(session.ToIDispatch(), "Timeout", 15000)
	if err != nil {
		return err
	}
	_ = v.Clear()
	for _, resource := range []string{"service", "service/auth", "client", "client/auth"} {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		v, err := oleutil.CallMethod(session.ToIDispatch(), "Get", "http://schemas.microsoft.com/wbem/wsman/1/config/"+resource)
		r := map[string]any{"Resource": resource, "Result": nativeCollectionResult(err)}
		if err == nil {
			projected, parseErr := projectRemoteConfiguration(v.ToString())
			_ = v.Clear()
			if parseErr != nil {
				err = parseErr
				r["Result"] = nativeCollectionResult(err)
			} else {
				r["Settings"] = projected
			}
		}
		if err != nil {
			c.failure(nativeCollectionResult(err))
		}
		if err := c.add(r); err != nil {
			return err
		}
	}
	return nil
}

func collectWMISecurity(c *assessmentCapture) error {
	queue := []string{"root"}
	for visited := 0; len(queue) > 0; visited++ {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if visited >= 256 {
			return errAssessmentLimit
		}
		namespace := queue[0]
		queue = queue[1:]
		err := func() error {
			service, err := wmiService(namespace)
			if err != nil {
				return err
			}
			defer service.Release()
			object, err := oleutil.CallMethod(service, "Get", "__SystemSecurity=@")
			if err != nil {
				return err
			}
			defer object.Clear()
			if object.ToIDispatch() == nil {
				return errors.ErrUnsupported
			}
			output, err := oleutil.CallMethod(object.ToIDispatch(), "ExecMethod_", "GetSD")
			if err != nil {
				return err
			}
			defer output.Clear()
			if output.ToIDispatch() == nil {
				return errors.ErrUnsupported
			}
			v, err := oleutil.GetProperty(output.ToIDispatch(), "ReturnValue")
			if err != nil {
				return err
			}
			code := v.Val
			_ = v.Clear()
			if code != 0 {
				return syscall.Errno(code)
			}
			sd, err := oleutil.GetProperty(output.ToIDispatch(), "SD")
			if err != nil {
				return err
			}
			defer sd.Clear()
			bytes, err := comValue(sd)
			if err != nil {
				return err
			}
			return c.add(map[string]any{"Namespace": namespace, "SecurityDescriptor": bytes, "Result": nativeCollectionResult(nil)})
		}()
		if err != nil {
			c.failure(nativeCollectionResult(err))
			if err := c.operation(namespace+":security", err); err != nil {
				return err
			}
		}
		err = wmiRecords(c, namespace, "__Namespace", []string{"Name"}, "", func(r map[string]any) error {
			name, ok := r["Name"].(string)
			if !ok || name == "" || strings.ContainsAny(name, `\/'"`) {
				return errors.ErrUnsupported
			}
			if visited+len(queue) >= 256 {
				return errAssessmentLimit
			}
			queue = append(queue, namespace+`\`+name)
			return nil
		})
		if err != nil {
			c.failure(nativeCollectionResult(err))
			if err := c.operation(namespace+":children", err); err != nil {
				return err
			}
		}
	}
	return nil
}

func collectDCOMSecurity(c *assessmentCapture) error {
	if err := collectRegistryDescriptors(c, `SOFTWARE\Microsoft\Ole`, []string{"DefaultAccessPermission", "DefaultLaunchPermission", "MachineAccessRestriction", "MachineLaunchRestriction"}); err != nil {
		return err
	}
	settings, err := registryAssessment(c, registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Ole`, []string{"LegacyAuthenticationLevel", "LegacyImpersonationLevel"})
	if err != nil {
		return err
	}
	registryStrings(c, registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Ole`, settings, []string{"EnableDCOM"}, nil)
	if err := c.add(settings); err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Classes\AppID`, registry.ENUMERATE_SUB_KEYS|registry.WOW64_64KEY)
	if err != nil {
		return err
	}
	defer key.Close()
	names, err := key.ReadSubKeyNames(4097)
	if len(names) > 4096 {
		return errAssessmentLimit
	}
	// ReadSubKeyNames(n) may return EOF together with the final partial batch.
	if err != nil && !errors.Is(err, io.EOF) {
		c.failure(nativeCollectionResult(err))
	}
	if err != nil && len(names) == 0 && !errors.Is(err, io.EOF) {
		return err
	}
	for _, name := range names {
		if !strings.HasPrefix(name, "{") {
			continue
		}
		if err := collectRegistryDescriptors(c, `SOFTWARE\Classes\AppID\`+name, []string{"AccessPermission", "LaunchPermission"}); err != nil {
			return err
		}
	}
	return nil
}

func collectRegistryDescriptors(c *assessmentCapture, path string, fields []string) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		if !errors.Is(err, registry.ErrNotExist) {
			c.failure(nativeCollectionResult(err))
		}
		return c.add(map[string]any{"Path": path, "Result": nativeCollectionResult(err)})
	}
	defer key.Close()
	for _, field := range fields {
		value, _, err := key.GetBinaryValue(field)
		if len(value) > 1<<20 {
			return errAssessmentLimit
		}
		r := map[string]any{"Path": path, "Value": field, "Result": nativeCollectionResult(err)}
		if err == nil {
			r["SecurityDescriptor"] = value
		} else if !errors.Is(err, registry.ErrNotExist) {
			c.failure(nativeCollectionResult(err))
		}
		if err := c.add(r); err != nil {
			return err
		}
	}
	return nil
}
