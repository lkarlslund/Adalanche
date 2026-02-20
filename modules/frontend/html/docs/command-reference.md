# Command Reference

This page documents what the OSS CLI options do in practice, based on the current code in this workspace.

For exact availability in your binary, still check:

```bash
adalanche --help
adalanche <command> --help
```

## Command model

Adalanche has three layers of configuration, in this order:

1. command-line flags
2. environment variables prefixed with `ADALANCHE_`
3. `configuration.yaml` in your datapath (default `data/configuration.yaml`)

The datapath is created automatically if it does not exist.

## Root command

```text
adalanche [command]
```

### Global flags and behavior

- `--datapath`
  - Base folder for reads/writes, including imported data, generated profiling files, and persistence database.

- `--loglevel`
  - Console log verbosity.

- `--logfile`, `--logfilelevel`
  - Enables file logging. `--logfile` supports `{timestamp}` replacement with current date.

- `--logzerotime`
  - Logs elapsed time since start instead of wall-clock time.

- `--embeddedprofiler`
  - Starts Go's pprof HTTP listener on localhost, starting at port `6060` and incrementing if occupied.

- `--cpuprofile`, `--cpuprofiletimeout`
  - Writes `adalanche-cpuprofile-*.pprof` to datapath.
  - Timeout > 0 auto-stops capture.

- `--memprofile`, `--memprofiletimeout`
  - Writes `adalanche-memprofile-*.pprof` heap profile to datapath.
  - Timeout > 0 auto-stops capture.

- `--fgtrace`
  - Writes `adalanche-fgtrace-*.json` to datapath.

- `--fgprof`
  - Writes `adalanche-fgprof-*.json` to datapath.

## analyze

```text
adalanche analyze [flags]
```

Launches the web UI, starts background analysis loading, and waits until the web service exits.

### Runtime behavior

- Sets Go memory limit to 80% of available memory.
- Sets GC target (`GOGC`) to 35.
- Applies `automaxprocs` to match container/CPU constraints.
- Starts web service before analysis is fully finished so UI can show progress/status.

### Flags

- `--bind`
  - Bind address for the web service. Default: `127.0.0.1:8080`.

- `--nobrowser`
  - Prevents automatic browser launch.

- `--certificate`, `--privatekey`
  - Intended to enable HTTPS for the web service.
  - Can be file paths or inline PEM values.

- `--importcnf`
  - Include AD conflict objects (`\0ACNF:` DN pattern) during analysis.

- `--importdel`
  - Include deleted AD objects (`\0ADEL:` DN pattern) during analysis.

- `--importhardened`
  - Include objects missing `objectClass`.

- `--warnhardened`
  - Emit warnings for objects missing `objectClass`.

- `--limitattributes`
  - Uses reduced AD attribute import to lower memory usage.

## collect

```text
adalanche collect [subcommand]
```

`collect` is a container command. Subcommands depend on what was compiled into your binary.

## collect activedirectory

```text
adalanche collect activedirectory [flags]
```

Collects AD data by one of three paths:

1. live LDAP collection
2. AD Explorer snapshot import (`--adexplorerfile`)
3. NTDS.DIT import (`--ntdsfile`)

### Connection and auth flags

- `--autodetect`
  - Attempts to auto-fill domain/server/auth context from environment and DNS.

- `--server`
  - Explicit domain controller list. If omitted, autodetection tries to find DCs.

- `--domain`
  - Domain suffix to analyze.

- `--port`
  - LDAP port override. `0` means auto based on TLS mode.

- `--tlsmode`
  - Transport mode: `NoTLS`, `StartTLS`, or `TLS`.

- `--channelbinding`
  - Enables LDAP channel binding on supported flows.

- `--ignorecert`
  - Skips certificate validation for TLS LDAP.

- `--authmode`
  - Bind mode selection (`anonymous`, `simple`, `digest`, `kerberoscache`, `ntlm`, `ntlmpth`, etc.).

- `--authdomain`, `--username`, `--password`
  - Explicit credentials.
  - If username is set and password omitted, interactive password prompt is used.
  - Password value `!` means intentionally blank password.

### Data scope and performance flags

- `--attributes`
  - `*` imports all attributes.
  - Comma-separated list limits attributes from LDAP fetch.

- `--pagesize`
  - LDAP paged-search page size.

- `--obfuscatedquery`
  - LDAP object filter used for broad AD pulls. Default is `(objectclass=*)`.

- `--nosacl`
  - Requests security descriptors with NO SACL flag for broader compatibility.

- `--configuration`, `--schema`, `--other`, `--objects`, `--gpos`
  - Per-context collection toggles (`auto`, true/false-like values).

- `--gpopath`
  - Overrides where GPO files are read from (useful on non-Windows/mounted SYSVOL).

- `--ldapdebug`
  - Enables LDAP debug output.

- `--purgeolddata`
  - Removes prior matching collection data in datapath after successful connection.

### Import-mode flags

- `--adexplorerfile`
  - Imports AD data from Sysinternals AD Explorer snapshot.

- `--adexplorerboost`
  - Loads snapshot into RAM first to speed decode.

- `--ntdsfile`
  - Imports AD objects from NTDS.DIT source.

## collect localmachine

```text
adalanche collect localmachine
```

If present in your build, gathers local machine telemetry and writes JSON into datapath.

Output naming behavior:
- domain joined: `<COMPUTER>$<DOMAIN>.localmachine.json`
- non-domain: `<COMPUTER>.localmachine.json`

## quick

```text
adalanche quick
```

Convenience workflow that runs:

1. `adalanche collect activedirectory`
2. `adalanche analyze`

On Windows, if started without arguments, quick mode is auto-selected.

## persistence

```text
adalanche persistence [dump|restore]
```

Operates on `persistence.bbolt` inside datapath.

- `dump --output <file>`
  - Dumps bucket/key/value data as JSON-like output.

- `restore --input <file>`
  - Command exists, but current OSS implementation is a stub and does not restore data.

## version

```text
adalanche version
```

Prints short version information.
