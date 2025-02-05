<div class="title">
<img class="only-light" src="../icons/adalanche-logo-black.svg#gh-light-mode-only" height="256px"><img class="only-dark" src="../icons/adalanche-logo.svg#gh-dark-mode-only" height="256px">
<br>
Adalanche Documentation
</div>

# Overview

This documentation covers both the open source edition and the paid enterprise versions (see [purchasing](#purchase-the-commercial-version) information). Some features are only available in the enterprise version, and the documentation will indicate which features are available in each version (indicated with an asterisk).

## How it works

Adalanche reads data, it never changes things in your infrastructure. This is a key element of the tool, and this ensures that you will not endanger anything by doing collections from Active Directory, local machines or other supported infrastructure components. You can run it with a normal user account and get 80% insight, but if you want complete coverage you need to collect from Active Directory with Domain Admin permissions and with elevated rights from local machines.

Trying Adalanche is easy - either with sample data or data collected from your own infrastructure.

# Installing Adalanche

Adalanche is an all-in-one binary - it collects information from Active Directory or from local Windows machines and can the analyze the collected data. If you're only doing AD analysis, just grab the binary for your preferred platform. Later you can deploy the dedicated collector .exe for your Windows member machines via a GPO or other orchestration and get even more insight.

Since Adalanche is built in Go, it should run on any [supported OS version](https://go.dev/wiki/MinimumRequirements). The primary binary is built with the latest stable version of Go, and the collector version with the older version of Go 1.11 to ensure compatibility with older systems. There are no runtime requirements, external libraries or other dependencies.

You have three options to get Adalanche up and running on your system:

## Download binaries from GitHub

Download either the latest [release](https://github.com/lkarlslund/Adalanche/releases/latest) or recent [development build](https://github.com/lkarlslund/Adalanche/releases/tag/devbuild). If you want the latest features and experiments try the latest development builds - it won't break your system, but things might be broken inside Adalanche when I'm doing experiments, refactoring or I make a mistake. 

Releases are considered stable and are for the less adventurous.

## Build the Open Source version

If you prefer full control, you can roll your own on any supported platform (Windows, MacOS, Linux, FreeBSD etc.):

Prerequisites:
- [Go 1.23 or later](https://go.dev/doc/install)
- [PowerShell 7](https://github.com/PowerShell/powershell/releases)
- [Git](https://git-scm.com/downloads) or direct download of the source code.

Clone the repository and run the build script:
```
git clone https://github.com/lkarlslund/Adalanche Adalanche
cd Adalanche
./build.ps1
```
Resulting binaries are available in the 'binaries' subfolder, and you will get the same result as the official releases, with the added benefit of being able to customize the build process if you want to. 

## Purchase the commercial version

Even though Adalanche is a labor of love, it's a personal one man project, paid for entirely by myself. Thousands of hours has been put into this, and if you work for a company that gets real value out of this, I urge you to consider purchasing a license. These purchases allows me to continue to work on Adalanche and for it to exist as a open source product.

Commercial licenses can be bought from from [NetSection](https://www.netsection.com), but feel free to reach out via email or DM me on any social platforms we share. I also do lots of consulting work, so you don't have to be a security expert in order to figure out what to do to get your Active Directory back into shape.

# Running Adalanche for the first time

## Run with sample data

If you're not keen on running foreign tools against your Active Directory, there are sample data available in [this](https://github.com/lkarlslund/adalanche-sampledata) repository. Instructions on how to run Adalanche with the sample data is in the readme file in this repository.

## Quick start / Easy mode

If you're running Adalanche on a Windows domain joined machine should just work *without any parameters*, as Adalanche tries to autodetect as much as it can. Under this scenario, and with parameters given, you will run in a collect-analyze mode (collect from Active Directory, then analyze).

For more advanced use (recommended) first collect, with proper options. All your data files will end up in the data subfolder (or use the general option <code>--datapath dir</code> to use an alternative folder).

See program options for other possibilities (help or command --help).

## Run with your own data

See [collecting data](#collecting-data-from-active-directory) and doing [analysis](#analysis) for general usage with your own data.

# Collecting data from Active Directory

This section describes how to collect data from Active Directory using Adalanche. For way more insight, you'll also need to [deploy the local machine collector](collecting-localmachine-data.md), which gives you way more information in the graph - I can't stress enough how important this part is.

## Triggering alarms

If you're using Microsoft Defender for Identity, you will most likely trigger alarms when doing this collection.  Adalanche asks for all the data it can get from your environment, using the LDAP filter "(objectClass=*)". 

As of summer 2024 Microsoft Defender for Identity will trigger an alarm when it detects enumeration queries against Active Directory - even wide and generic ones like the one that Adalanche defaults to. This is because a similar pattern could be used by a real attacker as part of the reconnaissance phase.

Microsoft Defender also detects Adalanche on the binary level (yay!) and will trigger an alarm when it sees Adalanche running in your environment. It does not block Adalanche from running, but you will see an alert in the cloud from Microsoft Defender on the endpoint that runs it.

If you want to try to evade detection, you can change the query using the <code>--objectfilter</code> option, or look into using the obfuscating [LDAPX proxy](https://github.com/Macmod/ldapx) project to route your traffic through. You can also try to obfuscate a compile of Adalanche from source, but this is left as an exercise for the reader.

As Adalanche is not meant to be a tool for the blue team, no evasion techniques will be added to Adalanche unless Microsoft chooses to force my hand by actively blocking Adalanche from running in their AV part on the endpoint by misclassification as malware.

[!NOTE] Note on command line options

Some options are global options (they need to come before the command) and other are command specific (and need to come after the command). Logging, profiling, setting the datapath etc. are global options. Use "--help" to figure it out :-)

## Run a collection from Active Directory

The primary source of data is from Active Directory though, and is intiated with this command:

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
This is a "Channel Binding" requirement for SSL enabled connections over LDAP, as part of Microsofts hardening efforts on making LDAP more secure. You will need to use Windows and the default native LDAP mode to collect data.

## Dump data using SysInternals AD Explorer

Uou can import data that has been exported from Active Directory using SysInternals [AD Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer). This is a GUI application that allows you to poke around in all objects and see all attributes. 

It also leverages the Windows LDAP library (just like Users & Computers etc.), and might be an option if you're not allowed to run Adalanche directly due to security concerns. 

By utilizing the "snapshot" feature, it allows you do dump the entire AD into a proprietary file, which Adalanche can ingest as an alternative to talking directly to LDAP.

The procedure for using AD Explorer as a data source is:

- Launch AD Explorer
- Connect to your domain, for simple setups you can just leave all fields blank and press connect
- Choose File | Create snapshot ... and save the file somewhere. There is no progress indicator, so just have patience
- Run Adalanche to collect Active Directory object and GPO data:
<code>adalanche collect activedirectory --adexplorerfile=yoursavedfile.bin</code>

You can delete the AD Explorer data file now, as this has been converted into Adalanche native format, and you can now run analysis on the data produced.

## GPO import options

For non-domain joined machines or alternative platforms like OSX or Linux, you can't reach the SYSVOL by UNC path. In that case, you have two options:

- Copy the Group Policy folder from SYSVOL and point to that with <code>--gpopath=your-copied-GPO-folder</code>, but you'll lose ACL analysis for the individual GPO files.
- Use the <code>--gpos=false</code> flag to disable GPO imports

You will then have compressed AD data (and potentially GPO data) in your datapath like a normal collection run. 

# Collecting data from Windows machines

Adalanche supports multiple data sources, and merges data from them when doing analysis. Getting insight into your domain joined Windows infrastructure give you lots of data to do attack path mapping on, as each imported machine generates objects from:

- users, groups
- assigned rights
- services, executables, registry keys
- fileshares and permissions
- installed software
- ... and lots more

This will give you insight into who uses what systems, service accounts that are domain users, autoadminlogins, who are local admins, who can RDP into systems and more fun stuff later on :-)

Computer data generates multiple thousands of objects and give deep insight into vulnerabilities, and allows you to do very deep searches.

Collection runs only use one CPU thread and typically takes less than a minute. In addition, the collection runs are very lightweight and should not impact your systems.

The idea is that you orchestrate it centrally with a Scheduled Task via a GPO or whatever means you see fit (psexec, login script etc). The collector will get more information if it is run with elevated privileges, but can provide parital information when run as an unpriviliged user.

The output files will automatically be imported into Adalanche when you run it, if they're part of your datapath (in a subfolder or just copied in - whatever works for you)

## Collecting data

The Adalanche collector binary has been designed to be compiled with an old version of Go, and supports Windows 7 / Windows Server 2008 R2 and up is supported.

The 32-bit Windows version of the collector works transparently also on 64-bit systems.

Usage:

<code>
adalanche-collector --datapath \\some\unc\path collect localmachien
</code>

You can also use the primary Adalanche binary as a collector, but since it requires a very recent Go version, only Windows versions from Windows 10 / Windows Server 2016 and up is supported using the all in one binary. Collecting test data from your analyst machine is easy by just running this manually.

## Deploying collector

You can deploy the collector using a GPO with a scheduled task. This is a suggested way to do it, but any orchestration you have available will do the job (intune, psexec, netexec). There is nothing to install, you just have to run the collector. 

Preferably run the collector with elevated rights in order to be able to collect all the data required.

An easy way to do this is to:

1. Create fileshare for the binary

Either create a dedicated fileshare for the binary, or place it on SYSVOL. Both strategies work, but ensure that only admins can change the binary. If you're using your own fileshare, make sure to use hardened UNC paths, otherwise this can become a weak point that attackers can abuse.

2. Create a fileshare for the resulting data files

Either create a dedicated fileshare for the data files, or place it on SYSVOL. Since these data files can contain sensitive data, ensure that "Domain Computers" or other similar group can write/append data, but not necessarily read any data.

If you use a subfolder of SYSVOL, be cautious of the space needed and the fact that SYSVOL is replicated among all domain controllers, and can burden WAN links etc.

3. Orchestrating with a GPO

Now that you have a place to run the binary from, and a place it can output data to, it's time to orchestrate it. Create a GPO with these settings:

- Scheduled Task
- Run as SYSTEM, with elevated rights
- Run when powering up, when a user logs in, or every N hours - whatever you think is appropriate
- Check the option "remove this item if it is no longer applied" so you can easily clean up if you no longer want to collect data

### 4. Copy resulting files

Once the binary has run and output its data files, you will need a way to copy these files off of the file share to your data folder location for analysis. This could be done via a tool like copy, robocopy or rsync that can be run from a central location to copy the files with a given interval. You can also YOLO it via Windows Explorer.

# Analysis

This is dead simple - everything you've collected should be in the data directory, either in the main folder or in subfolders.

Whatever resides there and Adalanche understands is automatically loaded, correlated and used. It's totally magic.

IMPORTANT: If you're doing multi domain or forest analysis, place all AD object and GPO files for each domain in their own subfolder, so Adalanche can figure out what to merge and what NOT to merge. When dumping just point to a new <code>--datapath</code> for collection run (example: <code>adalanche  --datapath=data/domain1 collect activedirectory --domain=domain1</code> or let Adalanche figure it out itself)

These extensions are recognized:
- .localmachine.json - Windows collector data
- .gpodata.json - Active Directory GPO data
- .objects.msgp.lz4 - Active Directory object/schema data in MsgPack format (LZ4 compressed)

Then analyze the data and launch your browser:

<code>adalanche analyze</code>

There are some options here as well - try <code>adalanche analyze --help</code>

# User Interface

<img src="images/welcome.png" width="80%">

When launched, you'll see some  statistics on what's loaded into memory and how many edges are detected between objects. Don't worry, Adalanche can handle millions of objects and edges, if you have enough RAM ;)

The pre-loaded query allows you to see who can pwn "Administrators", "Domain Admins" and "Enterprise Admins". Query target nodes are marked with RED. 

Press the "analyze" button in the query interface to get the results displayed. If you get a lot of objects on this one, congratz, you're running a pwnshop.

Depending on whether you're over or underwhelmed by the results, you can do adjustments or other searches.

#### Pre-defined searches

To ease the learning experience, there are a number of pre-defined queries built into Adalanche. You access these by pressing the "AQL queries" button, and choosing one. This should give you some idea of how to do queries, but see the dedicated page on that.

#### Analysis Options

<img src="images/analysis-options.png" width="50%">

##### Node Limit
If your query returns more than 200 objects (default), Adalanche will limit the output and give you the results that approximately fit within the limit. This limitation is because it has the potential to crash your browser, and is not an Adalanche restriction - feel free to adjust as needed.

##### Analysis Depth
Analysis depth allows you do override the maximum AQL search length. Setting this to 0 will only result in the first query node filter to be run - so don't prune islands here, otherwise you'll get nothing. Setting it to 1 results on only neighbouring edges to be returned. Quite useful if you get too much data back, blank is no restrictions.

##### Max Outgoing Edges (not working at the moment)
Limitimits how many outgoing edges are allowed from one object. This can help you limit the number of results.

##### Minimum (Edge) Probability
Restricts the graph to edges with a probability of at least this value. This can help you filter out less likely connections. This limit can be set on either a single node or the overall connection probability.

##### Prune Island Nodex
This option removes nodes that have no edges connecting them to other nodes from the results.

#### AQL Search pop-out
When you press the "AQL Search" tab on the bottom portion of the page, and you get the search interface:

<img src="images/aql-query.png" width="50%">

See the dedicated section on [AQL syntax](#aql-syntax) for more information on how to use this. There's an option to use pre-defined queries, save the current query and run the query.

### Operational theory

Adalanche works a bit differently than other tools, as it dumps everything it can from an Active Directory server, which it then saves to a highly compressed binary cache files for later use. This dump can be done by any unprivileged user, unless the Active Directory has been hardened to prevent this (rare).

If you collect GPOs I recommend using a Domain Admin account, as GPOs are often restricted to apply only to certain computers, and regular users can't read the files. This will limit the results that could have been gathered from GPOs.

The analysis phase is done on all collected data files, so you do not have to be connected to the systems when doing analysis. This way you can explore different scenarios, and ask questions not easily answered otherwise.

### Tagged nodes
In order to more quickly find certain nodes, Adalanche tags them with labels. Here's a list of some common tags:

| Tag | Description |
| --- | ----------- |
| hvt | High Value Target |
| role_domaincontroller | Domain Controller machines |
| role_readonly_domaincontroller | Read-Only Domain Controller machines |
| role_certificate_authority | Certificate Authority machines |
| laps | Machine is detected as having LAPS deployed |
| kerberoast | Account is kerberostable |
| asreproast | Account is ASREProastable |
| windows | Machine is running Windows |
| linux | Machine is running Linux |
| unconstrained | Account has unconstrained delegation set |
| constrained | Account has constrained delegation set |
| computer_account | Account for a domain joined computer |
| domaincontroller_account | Account for a domain controller |
| account_disabled | The account is disabled |
| account_enabled | The account is enabled |
| account_locked | The account is locked out |
| account_expired | The account has an expiration date that has expired |
| account_active | The account is enabled and not expired |
| account_inactive | The account is either disabled or expired |
| password_cant_change | Account is not allowed to have its password changed |
| password_never_expires | Password os not required to rotate password as set per password policy |
| password_not_required | Account is not required to have a password |

You can search for nodes with these tags using the 'tag' attribute.

### Analysis / Visualization
The tool works like an interactive map in your browser, and defaults to a ldap search query that shows you how to become "Domain Admin" or "Enterprise Admin" (i.e. member of said group or takeover of an account which is either a direct or indirect member of these groups).


## Edges

Adalanche detects various relationsships between nodes, represented as edges. These relationships are based on various attributes and permissions within Active Directory.

This list is not exhaustive, see complete list from within the UI.

| Edge | Explanation |
| -------- | ----------- |
| ACLContainsDeny | This flag simply indicates that the ACL contains a deny entry, possibly making other detections false positives. You can check effective permissions directly on the AD with the Security tab |
| AddMember | The entity can change members to the group via the Member attribute |
| AddMemberGroupAttr | The entity can change members to the group via the Member attribute (the set also contains the Is-Member-of-DL attribute, but you can't write to that) |
| AddSelfMember| The entity can add or remove itself to the list of members |
| AdminSDHolderOverwriteACL | The entity will get it's ACL overwritten by the one on the AdminADHolder object periodically |
| AllExtendedRights | The entity has all extended rights on the object |
| CertificateEnroll | The entity is allowed to enroll into this certificate template. That does not mean it's published on a CA server where you're alloed to do enrollment though |
| ComputerAffectedByGPO | The computer object is potentially affected by this GPO. If filtering is in use there will be false positives |
| CreateAnyObject | Permission in ACL allows entity to create any kind of objects in the container |
| CreateComputer | Permission in ACL allows entity to create computer objects in the container |
| CreateGroup | Permission in ACL allows entity to create group objects in the container |
| CreateUser | Permission in ACL allows entity to create user objects in the container |
| DCReplicationGetChanges | You can sync non-confidential data from the DCs |
| DCReplicationSyncronize | You can trigger a sync between DCs |
| DCsync | If both Changes and ChangesAll is set, you can DCsync - so this flag is an AND or the two others |
| DeleteChildrenTarget | Permission in ACL allows entity to delete all children via the DELETE_CHILD permission on the parent |
| DeleteObject | Permission in ACL allows entity to delete any kind objects in the container |
| DSReplicationGetChangesAll | You can sync confidential data from the DCs (hashes!). Requires DCReplicationGetChanges! |
| GenericAll | The entity has GenericAll permissions on the object, which means more or less the same as "Owns" |
| GPOMachineConfigPartOfGPO | Experimental |
| GPOUserConfigPartOfGPO | Experimental |
| HasAutoAdminLogonCredentials | The object is set to auto login using the entitys credentials which is stored in plain text in the registry for any user to read |
| HasMSA | |
| HasServiceAccountCredentials | The object uses the entitys credentials for a locally installed service, and can be extracted if you pwn the machine |
| HasSPN | The entity has a SPN, and can be kerberoasted by any authenticated user |
| HasSPNNoPreauth | The entity has a SPN, and can be kerberoasted by an unauthenticated user |
| LocalAdminRights | The entity has local administrative rights on the object. This is detected via GPOs or the collector module |
| LocalDCOMRights | The entity has the right to use DCOM against the object. This is detected via GPOs or the collector module |
| LocalRDPRights | The entity has the right to RDP to the object. This is detected via GPOs or the collector module. It doesn't mean you pwn the machine, but you can get a session and try to do PrivEsc |
| LocalSessionLastDay | The entity was seen having a session at least once within the last day |
| LocalSessionLastMonth | The entity was seen having a session at least once within the last month |
| LocalSessionLastWeek | The entity was seen having a session at least once within the last week |
| LocalSMSAdmins | The entity has the right to use SCCM Configuration Manager against the object. This is detected via the collector module. It does not mean that everyone are SCCM admins, but some are |
| MachineAccount |  |
| MachineScript | Same as above, just as either a startup or shutdown script. Detected via GPOs |
| MemberOfGroup | The entity is a member of this group |
| Owns | The entity owns the object, and can do anything it wishes to it |
| ReadLAPSPassword | The entity is allowed to read the plaintext LAPS password in the mS-MCS-AdmPwd attribute |
| ReadMSAPassword | The entity is allowed to read the plaintext password in the object |
| ResetPassword | The ACL allows entity to forcibly reset the user account password without knowing the current password. This is noisy, and will alert at least the user, who then no longer can log in. |
| ScheduledTaskOnUNCPath | The object contains a scheduled task that sits on a UNC path. If you can control the UNC path you can control what gets executed |
| SIDHistoryEquality | The objects SID-History attribute points to this entity, making them equal from a permission point of view |
| TakeOwnership | The entity can make itself the owner |
| WriteAll | The entity is allowed all write operations |
| WriteAllowedToAct | The entity is allowed to write to the ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity attribute of the object, so we can get it to accept impersonations what would otherwise not work |
| WriteAltSecurityIdentities | The entity is allowed to write to the Alt-Security-Identities attribute, so you can put your own certificate there and then authenticate as that user (via PKinit or similar) with this certificate |
| WriteAttributeSecurityGUID | The entity can write to the AttributeSecurityGUID. I'm not sure if this will work, but it has the potential to allows you to add an important attribute to a less important attribute set |
| WriteDACL | The entity can write to the DACL, effectively giving it all permissions after granting them |
| WriteExtendedAll | The entity is allowed to do all extended write operations |
| WriteKeyCredentialLink | The entity can write to the msDK-KeyCredentialLink attribute |
| WriteProfilePath | The entity can write to the user profile path of the user |
| WritePropertyAll | The entity can write to any property (same as above, ACL is just a bit different) |
| WriteScriptPath | The entity can write to the script path of the user, giving them instant remote execution when the user logs on |
| WriteSPN | The entity can freely write to the Service-Principal-Name attributes using SETSPN.EXE or similar tools. You can then kerberoast the account |
| WriteValidatedSPN | The entity can do validated writes to the Service-Principal-Name attributes using SETSPN.EXE or similar tools. You can then kerberoast the account |

## Plotting a path in the GUI

There is a right click menu on objects, so you can to searches in the displayed graph. First right click a target:

<img src="images/set-as-target.png" width="50%">

Then find a source to trace from:

<img src="images/route-to-target.png" width="50%">

If there's a connection from source to target, you'll get the entire attack path presented like this:

<img src="images/found-route.png" width="50%">

You can also pick any object on the graph, and perform an inbound or outbound search from it.

# Adalanche Query Language (AQL)

In order to query the internal Adalanche graph, you express your targets by issuing a search for starting nodes traversing zero to many edges and ending at a certain node.

Searches for nodes are defined more or less using LDAP query syntax, so the same options and requirements as when using eg. PowerShell with LDAP filters apply. Adalanche offers some more filters and expressions though in addition to standard AD LDAP filters.

## AQL Syntax

NOTE: Since [] is used as a literal in the queries themselves, parts of the query that are optional are enclosed in % below. If something is allowed repeatedly it's enclosed in %%.

aql = query %%UNION query%%

query = %searchtype% %label:%(nodefilter)-[edgefilter]%{n,m}%->%label:%(nodefilter)%%-[edgefilter]->%label:%(nodefilter)%%

## Graph search types (searchtype)

Graph traversal is done in a shortest path first order.

| Keyword | Description |
|---------|-------------|
| WALK | All traversals allowed, including loops etc. Not recommended. |
| TRAIL | Edges that are already part of the graph results are not allowed again |
| ACYCLIC | Nodes that are already part of the graph results are not allowed again. This is default search type if not specified. |
| SIMPLE | Neither edges nor nodes that are already part of the graph results are allowed more than once |

## Labels

You can label a group of nodes in the graph using the label: syntax in front of a node filter. Adalanche highlights nodes that have been tagged with "start" (red) and "end" (blue) in the UI, but you can use whatever you want.

## Node filters (nodefilter)

A node filter tells the query engine how to find nodes that are part of the graph. You can use basic LDAP syntax queryes, with these additional extensions:

<code>
name:(ldapfilter) ORDER BY attribute SKIP n LIMIT m
</code>

The name allows you to tag a group of nodes with a name, which currently is just used for highlighting the nodes in the UI, using the names "start" and "end". Later on this will become more useful for the queries themselves.

You might get too many results from a query - limit the selection of starting nodes with LIMIT 10 to just get the first 10 nodes (see LDAP queries below)

### LDAP filters
The tool has its own LDAP query parser, and makes it easy to search for other objects to take over, by using a familiar search language.

**The LDAP filters support these extensions:**
- case insensitive matching for all attribute names
- checking whether an attribute exists using asterisk syntax (member=*)
- case insensitive matching for string values using equality (=)
- integer comparison using <, <=, > and >= operators
- glob search using equality if search value includes ? or *
- case sensitive regexp search using equality if search value is enclosed in forward slashes: (name=/^Sir.*Mix.*lot$/ (can be made case insensitive with /(?i)pattern/ flags, see https://github.com/google/re2/wiki/Syntax)
- extensible match: 1.2.840.113556.1.4.803 (you can also use :and:) [LDAP_MATCHING_RULE_BIT_AND](https://ldapwiki.com/wiki/LDAP_MATCHING_RULE_BIT_AND) 
- extensible match: 1.2.840.113556.1.4.804 (you can also use :or:) [LDAP_MATCHING_RULE_BIT_OR](https://ldapwiki.com/wiki/LDAP_MATCHING_RULE_BIT_OR) 
- extensible match: 1.2.840.113556.1.4.1941 (you can also use :dnchain:) [LDAP_MATCHING_RULE_IN_CHAIN](https://ldapwiki.com/wiki/LDAP_MATCHING_RULE_IN_CHAIN) 
- custom extensible match: count - returns number of attribute values (member:count:>20 gives groups with more members than 20)
- custom extensible match: length - matches on length of attribute values (name:length:>20 gives you objects with long names)
- custom extensible match: since - parses the attribute as a timestamp and your value as a duration - pwdLastSet:since:<-6Y5M4D3h2m1s (pawLastSet is less than the time 6 years, 5 months, 4 days, 3 hours, 2 minutes and 1 second ago - or just pass an integer that represents seconds directly)
- synthetic attribute: _limit (_limit=10) returns true on the first 10 hits, false on the rest giving you a max output of 10 items
- synthetic attribute: _random100 (_random100<10) allows you to return a random percentage of results (&(type=Person)(_random100<1)) gives you 1% of users
- synthetic attribute: out - allows you to select objects based on what they can pwn *directly* (&(type=Group)(_canpwn=ResetPassword)) gives you all groups that are assigned the reset password right
- synthetic attribute: in - allows you to select objects based on how they can be pwned *directly* (&(type=Person)(_pwnable=ResetPassword)) gives you all users that can have their password reset
- glob matching on the attribute name - searching for (*name=something) is possible - also just * to search all attributes
- custom extensible match: timediff - allows you to search for accounts not in use or password changes relative to other attributes - e.g. lastLogonTimestamp:timediff(pwdLastSet):>6M finds all objects where the lastLogonTimestamp is 6 months or more recent than pwdLastSet
- custom extensible match: caseExactMatch - switches text searches (exact, glob) to case sensitive mode


## Edge filters

The edge filters allow you to specify one or more edge types that it needs to match in order to continue the search. If you don't specify anything (using blank filter <code>[]</code>), then Adalanche will use default edges, require at least 1 match, only traverse one edge and have no requirements for probabilities.

| Example | Edge filter |
|---------|-------------|
| Group memberships, depth 1-5 | [MemberOfGroup,MemberOfGroupIndirect]{1,5} |
| Next edge must have a of 100 | [probability=100] |
| Match two of X, Y and Z | [X,Y,Z,match=2] |
| Optional edge X | [X]{0,1} |
| Don't match X | [X,match=0] |
