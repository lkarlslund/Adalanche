# Collecting data from Windows machines

Adalanche merges multiple data sources during analysis. Local machine data adds deep context (users, groups, rights, services, executables, registry keys, shares, software, sessions, and more).

Collector runs are lightweight and typically quick. Elevated rights provide better coverage.

## Collecting data

The dedicated collector binary is intended for broad Windows compatibility.

Usage example:

```bash
adalanche-collector --datapath \\some\unc\path collect localmachine
```

You can also collect local machine data with the main binary where supported:

```bash
adalanche collect localmachine
```

Note: command availability can depend on build target/platform. Confirm on your build with:

```bash
adalanche collect --help
```

## Deploying collector

A common approach is deploying through GPO scheduled tasks, but any orchestration works (for example Intune, PsExec, NetExec).

Suggested approach:

1. Create a share for the binary
2. Create a share for output data files
3. Orchestrate with a scheduled task

Recommended task settings:
- Run as `SYSTEM` with elevated rights
- Trigger at startup, logon, or interval
- Enable cleanup when policy no longer applies

## Copy resulting files

After collection, copy result files from the share into your analysis datapath (for example with `robocopy` or `rsync`).
