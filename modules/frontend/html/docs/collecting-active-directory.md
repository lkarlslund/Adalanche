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

| Option | What it does | How to use it |
| --- | --- | --- |
| `--server` | Chooses which domain controller(s) to contact for live LDAP collection. If you supply multiple `--server` flags, Adalanche tries them in order until one works. If omitted, Adalanche tries to auto-detect DCs from DNS SRV records when `--autodetect` is enabled. | Use an IP or FQDN: `--server dc1.contoso.local`. Repeat the flag to provide fallbacks: `--server dc1.contoso.local --server dc2.contoso.local`. |
| `--domain` | Sets the AD DNS domain to analyze, such as `contoso.local`. This also feeds auto-detection and becomes the default authentication domain if `--authdomain` is not set. If omitted, Adalanche tries to detect it from the environment or host/domain context. | Use this when the machine is not domain joined, auto-detection is wrong, or you want to be explicit: `--domain contoso.local`. |
| `--authmode` | Controls how Adalanche binds to LDAP. Common values include `ntlm`, `negotiate`/`sspi` on Windows, `kerberoscache`, and `basic`/`simple`. The default is `ntlm` on the cross-platform collector and `negotiate` on the native Windows LDAP collector. | For username/password NTLM auth: `--authmode ntlm --username joe --password Hunter42`. On domain-joined Windows, the default integrated auth is usually enough. |
| `--tlsmode` | Chooses the transport security mode for LDAP. Valid values are `NoTLS`, `StartTLS`, and `TLS`. If `--port` is left at `0`, Adalanche automatically uses `389` for `NoTLS`/`StartTLS` and `636` for `TLS`. | Typical examples are `--tlsmode NoTLS` for standard LDAP or `--tlsmode TLS` for LDAPS. Use `StartTLS` only when your DC is configured for it. |
| `--ignorecert` | Disables certificate validation for TLS or StartTLS connections. This is useful for lab environments or private PKI setups, but it weakens connection security and should be avoided when proper trust can be configured. | Only use it together with encrypted LDAP modes when certificate validation would otherwise fail: `--tlsmode TLS --ignorecert`. |
| `--adexplorerfile` | Imports Active Directory objects from a Sysinternals AD Explorer snapshot instead of connecting to LDAP. When this is used, live LDAP connection options such as `--server`, `--domain`, `--authmode`, and `--tlsmode` are not needed for the object import itself. | Point it at a saved snapshot: `--adexplorerfile snapshot.bin`. You can still combine it with `--gpos` or `--gpopath` if you also want GPO file content collected. |
| `--gpos` | Controls whether Group Policy file contents are collected. It accepts `auto`, `true`, or `false`. In `auto` mode, Adalanche collects GPO files when it finds GPO references during AD object import. | Leave it as `auto` in normal cases. Use `--gpos=false` to skip SYSVOL/GPO file collection, or `--gpos=true` when you want to force it on. |
| `--gpopath` | Overrides the GPO file path used for GPO content collection. This is mainly for non-Windows or non-domain-joined systems where SYSVOL has been copied or mounted locally. When you override the path, Adalanche keeps importing file contents but disables GPO file ACL analysis. | Point it at the local folder that contains GPO GUID subdirectories: `--gpopath /mnt/sysvol/Policies`. This is commonly paired with `--gpos=true`. |
| `--obfuscatedquery` | Replaces the default LDAP filter `(objectclass=*)` used during live LDAP collection. This exists mainly for environments where broad LDAP enumeration may trigger detections. | Use only if you understand the tradeoff, because filtering too aggressively can reduce coverage. Example: `--obfuscatedquery \"(|(objectClass=user)(objectClass=group)(objectClass=computer))\"`. |

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
