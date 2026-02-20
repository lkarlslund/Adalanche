# Installing Adalanche

Adalanche is an all-in-one binary. It can collect information from Active Directory and local Windows machines, then analyze the collected data. If you only do AD analysis, use the main binary for your platform. Later, you can deploy the dedicated collector executable to Windows member machines for more coverage.

Since Adalanche is built in Go, it should run on any [supported OS version](https://go.dev/wiki/MinimumRequirements).

You have three options to get Adalanche running:

## Download binaries from GitHub

Download either the latest [release](https://github.com/lkarlslund/Adalanche/releases/latest) or the recent [development build](https://github.com/lkarlslund/Adalanche/releases/tag/devbuild).

Releases are considered stable. Development builds are useful if you want the newest features and are comfortable with occasional instability.

## Build the Open Source version

If you prefer full control, you can build from source on supported platforms.

Prerequisites:
- [Go 1.24.5 or later](https://go.dev/doc/install)
- [PowerShell 7](https://github.com/PowerShell/powershell/releases)
- [Git](https://git-scm.com/downloads) or direct source download

Build:
```bash
git clone https://github.com/lkarlslund/Adalanche Adalanche
cd Adalanche
./build.ps1
```

Resulting binaries are available in the `binaries` subfolder.

## Purchase the commercial version

Commercial licenses can be bought from [NetSection](https://www.netsection.com). You can also reach out to the maintainer directly.
