# <img src="modules/frontend/html/icons/adalanche-logo-black.svg#gh-light-mode-only" height="28px"><img src="modules/analyze/html/icons/adalanche-logo.svg#gh-dark-mode-only" height="28px"> Adalanche (Open Source)

*Active Directory Attack Graph Analyzer*

[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/lkarlslund/Adalanche)](https://github.com/lkarlslund/Adalanche/releases/latest) ![GitHub all releases](https://img.shields.io/github/downloads/lkarlslund/Adalanche/total) ![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/lkarlslund/Adalanche/prerelease.yml?branch=master)

<img align="right" src="readme-images/goad-graph.png" width="40%" alt="Sample Adalanche Graph using the GOAD lab">
Adalanche gives instant insight into what assigned permissions affect users and groups have in  Active Directory and surrounding infrastructure. It is useful for visualizing and exploring who can take over accounts, machines or the entire domain, and can be used to find and show misconfigurations.

## Ransomware attacks thrive on bad Active Directory configurations

Active Directory security is notoriously difficult. Small organizations generally have no idea what they're doing, and way too many people are just added to Domain Admins. In large organizations you have a huge number of people with different needs, and they are delegated access to varying degrees of power in the AD. At some point in time, someone makes a mistake, and that can cost you dearly.


## Current status

- A large AD with 500.000 objects results in a file approximately 250MB in size, but much larger ADs work fine too, just add more hardware
- Adalanche requires a reasonable amount of memory - loading and analyzing the above AD will use about 2.5GB RAM - but RAM is cheap, getting pwned is not
- There are probably mistakes, false positives and stuff I've overlooked. Feedback is welcome!
- There is an unsolved challenge with services that require multiple ACLs to pass (for instance Cert servers only lets members of "Users that can enroll" group use enrollment, while the Certificate Template lets "Domain Users" enroll - this looks like "Domain Users" can enroll to Adalanche). The same problem arises with fileshares, so this analysis is not done yet.

### Further reading on Active Directory attacks

If you need inspiration on how to use a detected attack path I can highly recommend that you take a look at both the [PayloadsAllTheThings Active Directory](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md) and [HackTricks Active Directory Methodology](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology) sites.

## Commercial Editions

Commercial editions with improved functionality are available for purchase from [NetSection](https://www.netsection.com). This is what funds the open source edition.

## Happy hunting!

Feedback is welcome -> BlueSky to [@lkarlslund](https://bsky.app/profile/lkarlslund.bsky.social) / Mastodon [@lkarlslund](https://infosec.exchange/@lkarlslund) / LinkedIn [Lars Karlslund](https://www.linkedin.com/in/lkarlslund/)
