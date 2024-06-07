package collect

import (
	"github.com/amidaware/taskmaster"
	"github.com/lkarlslund/adalanche/modules/integrations/localmachine"
	"github.com/lkarlslund/adalanche/modules/windowssecurity"
	"golang.org/x/sys/windows"
)

func ConvertRegisteredTask(rt taskmaster.RegisteredTask) localmachine.RegisteredTask {
	return localmachine.RegisteredTask{
		Name: rt.Name,
		Path: rt.Path,
		Definition: localmachine.TaskDefinition{
			Actions: func() []localmachine.TaskAction {
				a := make([]localmachine.TaskAction, len(rt.Definition.Actions))
				for i, v := range rt.Definition.Actions {
					a[i].Type = v.GetType().String()
					if e, ok := v.(taskmaster.ExecAction); ok {
						a[i].Path = e.Path
						a[i].Args = e.Args
						a[i].WorkingDir = e.WorkingDir

						if e.Path != "" {
							executable := resolvepath(e.Path)
							ownersid, dacl, err := windowssecurity.GetOwnerAndDACL(executable, windows.SE_FILE_OBJECT)
							if err == nil {
								a[i].PathOwner = ownersid.String()
								a[i].PathDACL = dacl
							}
						}
					}
				}
				return a
			}(),
			Context: rt.Definition.Context,
			Data:    rt.Definition.Data,
			Principal: localmachine.Principal{
				Name:      rt.Definition.Principal.Name,
				GroupID:   rt.Definition.Principal.GroupID,
				ID:        rt.Definition.Principal.ID,
				LogonType: int(rt.Definition.Principal.LogonType),
				RunLevel:  int(rt.Definition.Principal.RunLevel),
				UserID:    rt.Definition.Principal.UserID,
			},
			RegistrationInfo: localmachine.RegistrationInfo{
				Author:             rt.Definition.RegistrationInfo.Author,
				Date:               rt.Definition.RegistrationInfo.Date,
				Description:        rt.Definition.RegistrationInfo.Description,
				Documentation:      rt.Definition.RegistrationInfo.Documentation,
				SecurityDescriptor: rt.Definition.RegistrationInfo.SecurityDescriptor,
				Source:             rt.Definition.RegistrationInfo.Source,
				URI:                rt.Definition.RegistrationInfo.URI,
				Version:            rt.Definition.RegistrationInfo.Version,
			},
			// .Definition.RegistrationInfo,
			Settings: localmachine.TaskSettings{
				AllowDemandStart:          rt.Definition.Settings.AllowDemandStart,
				AllowHardTerminate:        rt.Definition.Settings.AllowHardTerminate,
				DeleteExpiredTaskAfter:    rt.Definition.Settings.DeleteExpiredTaskAfter,
				DontStartOnBatteries:      rt.Definition.Settings.DontStartOnBatteries,
				Enabled:                   rt.Definition.Settings.Enabled,
				TimeLimit:                 rt.Definition.Settings.TimeLimit.String(),
				Hidden:                    rt.Definition.Settings.Hidden,
				Priority:                  rt.Definition.Settings.Priority,
				RestartCount:              rt.Definition.Settings.RestartCount,
				RestartInterval:           rt.Definition.Settings.RestartInterval.String(),
				RunOnlyIfIdle:             rt.Definition.Settings.RunOnlyIfIdle,
				RunOnlyIfNetworkAvailable: rt.Definition.Settings.RunOnlyIfNetworkAvailable,
				StartWhenAvailable:        rt.Definition.Settings.StartWhenAvailable,
				StopIfGoingOnBatteries:    rt.Definition.Settings.StopIfGoingOnBatteries,
				WakeToRun:                 rt.Definition.Settings.WakeToRun,
			},
			Triggers: func() []string {
				a := make([]string, len(rt.Definition.Triggers))
				for i, v := range rt.Definition.Triggers {
					a[i] = v.GetType().String()
				}
				return a
			}(),
			XMLText: rt.Definition.XMLText,
		},
		Enabled:        rt.Enabled,
		State:          rt.State.String(),
		MissedRuns:     rt.MissedRuns,
		NextRunTime:    rt.NextRunTime,
		LastRunTime:    rt.LastRunTime,
		LastTaskResult: uint32(rt.LastTaskResult),
	}
}
