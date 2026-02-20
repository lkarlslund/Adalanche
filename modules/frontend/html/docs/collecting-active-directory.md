# Collecting data from Active Directory

This section describes how to collect data from Active Directory using Adalanche.

For significantly deeper insight, also collect local machine data (see [collecting data from Windows machines](collecting-windows-machines.md)).

## Triggering alarms

If you use Microsoft Defender for Identity, collection may trigger alerts. By default Adalanche requests broad LDAP data (`(objectClass=*)`), which can look like reconnaissance.

If needed, change the query with `--obfuscatedquery`.

As Adalanche is not designed as an evasion tool, built-in evasion features are intentionally limited.

## Command line options note

Some options are global and must come before the command (for example `--datapath`, logging, profiling). Command-specific flags come after the command.

Use `--help` to confirm placement.

## Run a collection from Active Directory

```bash
adalanche [--globaloptions ...] collect activedirectory [--options ...]
```

If you are on a non-domain-joined machine or non-Windows OS, you typically need at least `--domain`, `--username`, and `--password`.

Default LDAP mode is unencrypted (`--tlsmode NoTLS`, usually port 389). To use TLS (usually 636), set `--tlsmode TLS`.

Example from Linux with TLS and NTLM auth:

```bash
adalanche collect activedirectory --tlsmode TLS --ignorecert --domain contoso.local --authdomain CONTOSO --username joe --password Hunter42
```

Domain-joined Windows using current user:

```bash
adalanche collect activedirectory
```

Domain-joined Windows with explicit credentials:

```bash
adalanche collect activedirectory --authmode ntlm --username joe --password Hunter42
```

### Commonly used options

- `--server`
- `--domain`
- `--authmode`
- `--tlsmode`
- `--ignorecert`
- `--adexplorerfile`
- `--gpos`
- `--gpopath`
- `--obfuscatedquery`

Check the full and current list with:

```bash
adalanche collect activedirectory --help
```

## Troubleshooting

If collection fails, try switching TLS mode, certificate validation behavior, authentication mode, or collection source.

### LDAP RESULT CODE 49

- Wrong credentials:
  - invalid username/password or locked account.
- Channel binding requirements:
  - LDAP over SSL may require channel binding; using Windows native LDAP defaults can help.

## Dump data using SysInternals AD Explorer

You can import AD Explorer snapshots:

```bash
adalanche collect activedirectory --adexplorerfile=yoursavedfile.bin
```

Workflow:
- Launch AD Explorer
- Connect to domain
- Create snapshot
- Run Adalanche import command

## GPO import options

For non-domain-joined systems or non-Windows platforms:

- Copy Group Policy files locally and use `--gpopath`, or
- Disable GPO import with `--gpos=false`

The resulting data can still be analyzed normally.
