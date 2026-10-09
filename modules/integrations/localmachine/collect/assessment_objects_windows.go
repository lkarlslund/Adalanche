//go:build windows

package collect

import (
	"errors"
	"slices"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

func collectFirewallProfiles(c *assessmentCapture) error {
	policy, err := comObject("HNetCfg.FwPolicy2")
	if err != nil {
		return err
	}
	defer policy.Release()
	for i, name := range []string{"Domain", "Private", "Public"} {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		// This API exposes local profile settings, not an effective-policy verdict.
		record := map[string]any{"Name": name, "PolicyScope": "local", "EffectivePolicyKnown": false}
		for _, field := range []string{"FirewallEnabled", "DefaultInboundAction", "DefaultOutboundAction"} {
			value, err := oleutil.GetProperty(policy, field, int32(1<<i))
			if err != nil {
				return err
			}
			if field == "FirewallEnabled" {
				enabled, ok := value.Value().(bool)
				if !ok {
					_ = value.Clear()
					return errors.ErrUnsupported
				}
				record["Enabled"] = 2
				if enabled {
					record["Enabled"] = 1
				}
			} else {
				record[field] = "Block"
				if value.Val == 1 {
					record[field] = "Allow"
				}
			}
			_ = value.Clear()
		}
		if err := c.add(record); err != nil {
			return err
		}
	}
	return nil
}

func collectFirewallRules(c *assessmentCapture) error {
	policy, err := comObject("HNetCfg.FwPolicy2")
	if err != nil {
		return err
	}
	defer policy.Release()
	v, err := oleutil.GetProperty(policy, "Rules")
	if err != nil {
		return err
	}
	defer v.Clear()
	if v.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	return comEach(c.ctx, v.ToIDispatch(), func(rule *ole.IDispatch) error {
		enabled, err := oleutil.GetProperty(rule, "Enabled")
		if err != nil {
			return err
		}
		active, ok := enabled.Value().(bool)
		_ = enabled.Clear()
		if !ok {
			return errors.ErrUnsupported
		}
		if !active {
			return nil
		}
		r, err := comFields(rule, []string{"Name", "Direction", "Action", "Profiles", "Protocol", "LocalAddresses", "RemoteAddresses", "ApplicationName", "ServiceName", "InterfaceTypes"})
		if err != nil {
			return err
		}
		direction, action := "Inbound", "Block"
		if r["Direction"] == int32(2) {
			direction = "Outbound"
		}
		if r["Action"] == int32(1) {
			action = "Allow"
		}
		ports := map[string]any{"Protocol": r["Protocol"]}
		// Port getters are invalid for non-TCP/UDP protocols.
		if r["Protocol"] == int32(6) || r["Protocol"] == int32(17) {
			p, err := comFields(rule, []string{"LocalPorts", "RemotePorts"})
			if err != nil {
				return err
			}
			ports["LocalPort"], ports["RemotePort"] = p["LocalPorts"], p["RemotePorts"]
		}
		return c.add(map[string]any{
			"Name": r["Name"], "Direction": direction, "Action": action, "Profile": firewallProfileNames(r["Profiles"]),
			"Ports": []any{ports}, "Addresses": []any{map[string]any{"LocalAddress": r["LocalAddresses"], "RemoteAddress": r["RemoteAddresses"]}},
			"ApplicationName": r["ApplicationName"], "ServiceName": r["ServiceName"], "InterfaceTypes": r["InterfaceTypes"],
		})
	})
}

func firewallProfileNames(value any) string {
	mask, ok := value.(int32)
	if !ok {
		return "Unknown"
	}
	if mask == 0x7fffffff {
		return "Any"
	}
	var names []string
	for i, name := range []string{"Domain", "Private", "Public"} {
		if mask&(1<<i) != 0 {
			names = append(names, name)
		}
	}
	return strings.Join(names, ",")
}

func collectNativeTaskSecurity(c *assessmentCapture) error {
	scheduler, err := comObject("Schedule.Service")
	if err != nil {
		return err
	}
	defer scheduler.Release()
	connected, err := oleutil.CallMethod(scheduler, "Connect")
	if err != nil {
		return err
	}
	_ = connected.Clear()
	root, err := oleutil.CallMethod(scheduler, "GetFolder", `\`)
	if err != nil {
		return err
	}
	defer root.Clear()
	if root.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	root.ToIDispatch().AddRef()
	folders := []*ole.IDispatch{root.ToIDispatch()}
	defer func() {
		for _, folder := range folders {
			folder.Release()
		}
	}()
	for visited := 0; len(folders) > 0; visited++ {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		if visited >= 10000 {
			return errAssessmentLimit
		}
		folder := folders[len(folders)-1]
		folders = folders[:len(folders)-1]
		err := func() error {
			defer folder.Release()
			tasks, err := oleutil.CallMethod(folder, "GetTasks", 1)
			if err != nil {
				return err
			}
			defer tasks.Clear()
			if tasks.ToIDispatch() == nil {
				return errors.ErrUnsupported
			}
			err = comEach(c.ctx, tasks.ToIDispatch(), func(task *ole.IDispatch) error {
				record, err := comFields(task, []string{"Path"})
				if err != nil {
					return err
				}
				sd, err := oleutil.CallMethod(task, "GetSecurityDescriptor", 4)
				record["Result"] = nativeCollectionResult(err)
				c.failure(nativeCollectionResult(err))
				if err == nil {
					record["SDDL"] = sd.ToString()
					_ = sd.Clear()
				}
				return c.add(record)
			})
			if err != nil {
				return err
			}
			children, err := oleutil.CallMethod(folder, "GetFolders", 0)
			if err != nil {
				return err
			}
			defer children.Clear()
			if children.ToIDispatch() == nil {
				return errors.ErrUnsupported
			}
			return comEach(c.ctx, children.ToIDispatch(), func(child *ole.IDispatch) error {
				if visited+len(folders) >= 10000 {
					return errAssessmentLimit
				}
				child.AddRef()
				folders = append(folders, child)
				return nil
			})
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func collectNativeStartup(c *assessmentCapture) error {
	return wmiRecords(c, `root\cimv2`, "Win32_StartupCommand", []string{"Name", "Location", "User", "UserSID", "Command"}, "", func(r map[string]any) error {
		command, _ := r["Command"].(string)
		delete(r, "Command")
		r["Executable"] = startupExecutable(command)
		r["PathResolved"] = r["Executable"] != ""
		return c.add(r)
	})
}

func collectNativeEventSubscriptions(c *assessmentCapture) error {
	return wmiRecords(c, `root\subscription`, "__FilterToConsumerBinding", []string{"Filter", "Consumer", "CreatorSID"}, "", func(r map[string]any) error {
		for _, field := range []string{"Filter", "Consumer"} {
			path, _ := r[field].(string)
			object, err := comObject("WbemScripting.SWbemObjectPath")
			if err != nil {
				return err
			}
			err = func() error {
				defer object.Release()
				v, err := oleutil.PutProperty(object, "Path", path)
				if err != nil {
					return err
				}
				_ = v.Clear()
				class, err := comFields(object, []string{"Class"})
				if err != nil {
					return err
				}
				r[field+"Class"] = class["Class"]
				keys, err := oleutil.GetProperty(object, "Keys")
				if err != nil {
					return err
				}
				defer keys.Clear()
				if keys.ToIDispatch() == nil {
					return errors.ErrUnsupported
				}
				key, err := oleutil.CallMethod(keys.ToIDispatch(), "Item", "Name")
				if err != nil {
					return err
				}
				defer key.Clear()
				if key.ToIDispatch() == nil {
					return errors.ErrUnsupported
				}
				value, err := comFields(key.ToIDispatch(), []string{"Value"})
				if err != nil {
					return err
				}
				r[field+"Name"] = value["Value"]
				return nil
			}()
			if err != nil {
				return err
			}
			delete(r, field)
		}
		return c.add(r)
	})
}

func collectNativeEventConsumers(c *assessmentCapture) error {
	classes := map[string]bool{}
	err := wmiRecords(c, `root\subscription`, "__EventConsumer", []string{"__CLASS"}, "", func(r map[string]any) error {
		name, ok := r["__CLASS"].(string)
		if !ok || name == "" {
			return errors.ErrUnsupported
		}
		for _, ch := range name {
			if ch != '_' && !(ch >= 'A' && ch <= 'Z') && !(ch >= 'a' && ch <= 'z') && !(ch >= '0' && ch <= '9') {
				return errors.ErrUnsupported
			}
		}
		classes[name] = true
		return nil
	})
	if err != nil {
		return err
	}
	queries := []struct {
		class  string
		fields []string
		where  string
		script bool
	}{
		{"CommandLineEventConsumer", []string{"Name", "CreatorSID", "ExecutablePath"}, "", false},
		{"ActiveScriptEventConsumer", []string{"Name", "CreatorSID", "ScriptFileName"}, "ScriptText IS NULL", false},
		{"ActiveScriptEventConsumer", []string{"Name", "CreatorSID", "ScriptFileName"}, "ScriptText IS NOT NULL", true},
	}
	var otherClasses []string
	for class := range classes {
		if class != "CommandLineEventConsumer" && class != "ActiveScriptEventConsumer" {
			otherClasses = append(otherClasses, class)
		}
	}
	slices.Sort(otherClasses)
	for _, class := range otherClasses {
		// Custom consumers need not expose executable/script fields. Inventory
		// their identity without loading a payload or guessing their behavior.
		if err := wmiRecords(c, `root\subscription`, class, []string{"Name", "CreatorSID"}, "", func(r map[string]any) error {
			r["Class"] = class
			return c.add(r)
		}); err != nil {
			c.failure(nativeCollectionResult(err))
		}
	}
	for _, query := range queries {
		if !classes[query.class] {
			continue
		}
		err := wmiRecords(c, `root\subscription`, query.class, query.fields, query.where, func(r map[string]any) error {
			r["Class"], r["HasEmbeddedScript"] = query.class, query.script
			r["Executable"], r["ScriptFile"] = r["ExecutablePath"], r["ScriptFileName"]
			delete(r, "ExecutablePath")
			delete(r, "ScriptFileName")
			return c.add(r)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func collectWSMan(c *assessmentCapture, kind string) error {
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
	timeout, err := oleutil.PutProperty(session.ToIDispatch(), "Timeout", 15000)
	if err != nil {
		return err
	}
	_ = timeout.Clear()
	result, err := oleutil.CallMethod(session.ToIDispatch(), "Enumerate", "http://schemas.microsoft.com/wbem/wsman/1/config/"+kind)
	if err != nil {
		return err
	}
	defer result.Clear()
	if result.ToIDispatch() == nil {
		return errors.ErrUnsupported
	}
	for count := 0; ; count++ {
		if err := c.ctx.Err(); err != nil {
			return err
		}
		end, err := oleutil.GetProperty(result.ToIDispatch(), "AtEndOfStream")
		if err != nil {
			return err
		}
		done, ok := end.Value().(bool)
		_ = end.Clear()
		if !ok {
			return errors.ErrUnsupported
		}
		if done {
			return nil
		}
		if count >= 10000 {
			return errAssessmentLimit
		}
		xmlValue, err := oleutil.CallMethod(result.ToIDispatch(), "ReadItem")
		if err != nil {
			return err
		}
		raw := xmlValue.ToString()
		_ = xmlValue.Clear()
		if len(raw) > 1<<20 {
			return errAssessmentLimit
		}
		record, err := wsmanRecord(raw, kind)
		if err != nil {
			return err
		}
		if err := c.add(record); err != nil {
			return err
		}
	}
}
