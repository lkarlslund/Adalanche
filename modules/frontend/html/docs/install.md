## Get Adalanche

Adalanche is an all-in-one binary - it collects information from Active Directory or from local Windows machines and can the analyze the collected data. If you're only doing AD analysis, just grab the binary for your preferred platform. Later you can deploy the dedicated collector .exe for your Windows member machines via a GPO or other orchestration and get even more insight.

You have three options to get Adalanche up and running on your system:

### Download

Download either the latest [release](https://github.com/lkarlslund/Adalanche/releases/latest) or recent [development build](https://github.com/lkarlslund/Adalanche/releases/tag/devbuild). Usually running with the latest development build is fine, but there might be a problem here and there. Releases are considered stable and are for the less adventurous.

### Build it yourself

If you prefer full control, you can roll your own on any supported platform (Windows, MacOS, Linux):

- Prerequisites: Go 1.23, PowerShell 7, git
- <code>git clone https://github.com/lkarlslund/Adalanche Adalanche</code>
- <code>cd Adalanche</code>
- <code>./build.ps1</code>

Resulting binaries are available in the 'binaries' subfolder.

### Purchase the commercial version

Even though Adalanche is a labor of love, it's a personal one man project, paid for entirely by myself. Thousands of hours has been put into this, and if you work for a company that gets real value out of this, I urge you to consider purchasing a license. These purchases allows me to continue to work on Adalanche and for it to exist as a open source product.

Commercial licenses can be bought from from [NetSection](https://www.netsection.com), but feel free to reach out via email or DM me on any social platforms we share.
