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

Collection runs only use one CPU thread and typically takes less than a minute.

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

### Create fileshare for the binary

Either create a dedicated fileshare for the binary, or place it on SYSVOL. Both strategies work, but ensure that only admins can change the binary. If you're using your own fileshare, make sure to use hardened UNC paths, otherwise this can become a weak point that attackers can abuse.

### Create a fileshare for the resulting data files

Either create a dedicated fileshare for the data files, or place it on SYSVOL. Since these data files can contain sensitive data, ensure that "Domain Computers" or other similar group can write/append data, but not necessarily read any data.

If you use a subfolder of SYSVOL, be cautious of the space needed and the fact that SYSVOL is replicated among all domain controllers, and can burden WAN links etc.

### Orchestrating with a GPO

Now that you have a place to run the binary from, and a place it can output data to, it's time to orchestrate it. Create a GPO with these settings:

- Scheduled Task
- Run as SYSTEM, with elevated rights
- Run when powering up, when a user logs in, or every N hours - whatever you think is appropriate
- Check the option "remove this item if it is no longer applied" so you can easily clean up if you no longer want to collect data

