# Collecting data from Active Directory

Trying Adalanche is easy - either with sample data or data collected from your own infrastructure.

## Run with sample data

If you're not keen on running foreign tools against your Active Directory, there are sample data available in [this](https://github.com/lkarlslund/adalanche-sampledata) repository.

## Using data from your infrastructure

Adalanche reads data, it never changes things in your infrastructure. This is a key element of the tool, and this ensures that you will not endanger anything by doing collections from Active Directory, local machines or other supported infrastructure components.

If you're using Microsoft Defender for Identity, you might trigger an alarm when doing the collection. Adalanche asks for all the data it can get from your environment, using the LDAP filter "(objectClass=*)". After 4 years of having no problems with that, Microsoft now triggers an "enumeration" alert when it detects such a query. This is because a similar pattern could be used by a real attacker as part of the reconnaissance phase. 

If you want to try to evade detection, you can change the query using the <code>--objectfilter</code> option, or look into using the obfuscating [LDAPX proxy](https://github.com/Macmod/ldapx) project to route your traffic through.

### Easy mode / full auto

If you're running Adalanche on a Windows domain joined machine should just work *without any parameters*, as Adalanche tries to autodetect as much as it can. Under this scenario, and with parameters given, you will run in a collect-analyze mode (collect from Active Directory, then analyze).

For more advanced use (recommended) first collect, with proper options. All your data files will end up in the data subfolder (or use the general option <code>--datapath dir</code> to use an alternative folder).

See program options for other possibilities (help or command --help).

### Note on command line options

Some options are global options (they need to come before the command) and other are command specific (and need to come after the command). Logging, profiling, setting the datapath etc. are global options. Use "--help" to figure it out :-)

### Collecting data from Active Directory
The primary source of data is from Active Directory, and is intiated with this command:

<code>adalanche [--globaloptions ...] collect activedirectory [--options ...]</code>

*Windows versions of Adalanche will default to using the native Windows LDAP library to connect to Active Directory, while non Windows version will use the Go multiplatform LDAP library. You can force Adalanche on Windows to use the multiplatform library with the <code>--nativeldap=false</code> option - this allows you to use a hash as a password and also to use a kerberos cache file for authentication.*

| Feature | Windows LDAP | Multiplatform LDAP |
| ------- | ------------ | ------------------ |
| Unauthenticated bind | Yes | Yes |
| Simple bind | Yes | Yes |
| Digest bind | Yes | Yes |
| Kerberos | Yes, via NEGOTIATE | Yes (cache file) |
| NTLM | Yes | Yes |
| NTLM (hash) | No | Yes |

If you're on a non-domain joined Windows machine or another OS, you'll need at least the <code>--domain</code> parameter, as well as username and password (you'll be prompted for password if Adalanche needs it and you didn't provide it on command line - beware of SysMon or other command line logging tools that might capture your password).

LDAP (unencrypted port 389) is default. You can switch to TLS (port 636) with <code>--tlsmode tls</code> option. 

Example to create data files file for contoso.local coming from your Linux pwnage box using TLS port 636, ignoring certs and using NTLM auth:

<code>adalanche collect activedirectory --tlsmode tls --ignorecert --domain contoso.local --authdomain CONTOSO --username joe --password Hunter42</code>

From domain joined Windows member using current user:

<code>adalanche collect activedirectory</code>

From domain joined Windows machine using other credentials than logged in:

<code>adalanche collect activedirectory --authmode ntlm --username joe --password Hunter42</code>

There are more options available, for instance on what LDAP contexts to collect, whether to collect GPOs or not etc. Please be aware that you can collect GPOs from Linux by mounting sysvol locally and pointing Adalanche to this path for GPO collection - but you will lose ACL analysis for the individual files.

## Troubleshooting

You might run into problems when collecting from Active Directory, then try switching from NoTLS to TLS, disable certificate checks, use another authentication protocol etc. Running from a domain joined Windows machine is the easiest way. 

Here are some common error codes you might see: 

### LDAP RESULT CODE 49

- __Wrong credentials (username/password)__
"LDAP Result Code 49 "Invalid Credentials": 8009030C: LdapErr: DSID-0C0906B5, comment: AcceptSecurityContext error, data 52e, v4563"
You've entered wrong credentials or the account is blocked.

- __Channel binding requirements__
"LDAP Result Code 49 "Invalid Credentials": 80090346: LdapErr: DSID-0C0906B5, comment: AcceptSecurityContext error, data 80090346, v4563"
This is a "Channel Binding" requirement for SSL enabled connections over LDAP, as part of Microsofts hardening efforts on making LDAP more secure.  This is currently unsupported by Adalanche on non Windows platforms due to LDAP library limitations - try running the collection from a Windows machine.

### Dump data using SysInternals AD Explorer

Uou can import data that has been exported from Active Directory using SysInternals [AD Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer). This is a GUI application that allows you to poke around in all objects and see all attributes. 

It also leverages the Windows LDAP library (just like Users & Computers etc.), and might be an option if you're not allowed to run Adalanche directly due to security concerns. 

By utilizing the "snapshot" feature, it allows you do dump the entire AD into a proprietary file, which Adalanche can ingest as an alternative to talking directly to LDAP.

The procedure for using AD Explorer as a data source is:

- Launch AD Explorer
- Connect to your domain, for simple setups you can just leave all fields blank and press connect
- Choose File | Create snapshot ... and save the file somewhere. There is no progress indicator, so just have patience
- Run Adalanche to collect Active Directory object and GPO data:
<code>adalanche collect activedirectory --adexplorerfile=yoursavedfile.bin</code>

### GPO import options

If you can't reach GPOs from where you're importing, you can either disable GPO imports <code>--gpos=false</code> or copy the Group Policy folder from SYSVOL and point to that with <code>--gpopath=your-copied-GPO-folder</code>, but you'll lose ACL analysis for the individual GPO files.

You will then have compressed AD data (and potentially GPO data) in your datapath like a normal collection run. You can delete the AD Explorer data file now, as this is converted into Adalanche native format, and you can now run analysis mode.
