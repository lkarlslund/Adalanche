# adalanche - Active Directory ACL Visualizer and Explorer

## I Can Haz Domain Admin?
Active Directory security is notoriously difficult. Small organizations generally have no idea what they're doing, and way too many people are just added to Domain Admins. In large organizations you have a huge number of people with different needs, and they are delegated access to varying degrees of power in the AD. At some point in time, someone makes a mistake, and that can cost you dearly.

### Run adalanche on your own infrastructure
You should ensure you have permission before you run this :-) Though the software is harmless any only uses the LDAP service to read data *any user* can access, your infrastructure/SOC team might get real mad at you none the less.

#### Quick start:
- Download latest release from Releases
- Build your own:
  - Install go 1.15+
  - <code>go build</code>
  - You will have a binary for your OS

If no command is given, the tool will run in a dump-analyze mode (dump, then analyze).

The tool tries to autodetect as much as it can, so running it on a domain joined machine will only require the -password parameter:
<code>adalanche.exe -password Hunter42</code>

If you're on a non-domain joined Windows machine or another OS, you'll need at least the -domain parameter as well. 

Create cache file for contoso.local:
<code>adalanche -domain contoso.local -username joe -password Hunter42 dump</code>

Analyze cache file for contoso.local and launch browser:
<code>adalanche -domain contoso.local analyze</code>

### User Interface
When launched, you get to see who can pwn "Domain Admins" and "Enterprise Admins". Query targets are marked with RED. If you get a lot of objects on this one, congratz, you're running a pwnshop.

The below examples loaded from the included domain beyond.local, which is a synthetic domain, that has been heavy handedly been messed up using [BadBlood](https://github.com/davidprowe/BadBlood). You can try the same analysis with:
<code>adalanche -domain beyond.local analyze</code>

Your browser should pop up with:
<img src="readme-images/welcome.png" width="80%">

No really exciting results on this synthetic AD. Yes, some users are Domain Admins and Administrators. But let's expand the search a bit.

#### Analysis Methods
Press the "Analysis Methods" tab on the bottom portion of the page, and you get this:

<img src="readme-images/analysis-methods.png" width="50%">

The tool can look for many scenarios, but defaults to fairly simple ones that can get you control of an object. As this yielded nothing, let's try to expand with all methods enabled. Checking the missing boxes, we submit another query.

#### LDAP query pop-out
When you press the "LDAP Query" tab on the bottom portion of the page, and you get the search interface:

<img src="readme-images/ldap-query.png" width="50%">

"Quieries" button is just for inspiration, with some predefined queries to get you going. 
"Safe"/"Force" button allows you to run requests that returns more than 1000 objects (potentially crashing your browser tab). 
"Max Depth" can limit results by not going further from a target than this depth.

Analyze:
- Normal searches for other objects that can pwn the selection in your LDAP query (i.e. who can reach these objects)
- Reverse searches for objects that you LDAP query targets can pwn (i.e. what can these objects reach)
- Limited means the search stops when it reaches Enterprise Admins / Domain Admins / Administrators groups **experimental**
- Complete means the search finds all pwn paths between implicated objects. This potentially makes the returned graph very edge heavy if your AD is a mess :-)

I enabled "Force" as I was warned that the analysis would return more than 1000 objects, and pressed "Analyze / Normal".

<img src="readme-images/query-with-all-methods.png" width="80%">

Whoa - that's a lot. But can all these objects then suddenly do a system takeover? No, not neccesarily, this depends on the analysis methods used. We enabled the CanDelete*, CanCreate* and InheritsSecurity methods.

Let's investigate what's going on here - right click on one of your targets, and choose "Set as target". 
<img src="readme-images/set-as-target.png" width="30%">

Then right-click on someone else, and choose "Route to target".

<img src="readme-images/route-to-target.png" width="30%">

Then you'll get a route, which shows the best way to the target.

<img src="readme-images/found-route.png" width="40%">

So here the problem is just a matter of groups being nested members of other groups, but at the very end you see that someone set the DELETE_CHILD flag on the parent container, yielding the right to delete (or potentially move) the target. That does look wrong, doesn't it?

If you examine the "Domain Users" object, you will see that it doesn't have the InheritsSecurity flag, so you can't really pwn it by moving it around.

So try it out on your own data - see what your user can pwn by searching for (&(objectCategory=Person)(Name=YOURLOGIN)) and do a Reverse search. Maybe you'll just end up with the groups that you are a member of, maybe you have access to more than you think ...

| Question | LDAP query | Depth | Methods | Analysis |
|----------|------------|-------|---------|----------|
| Who can directly reset passwords? | (&(\|(objectCategory=Group)(objectCategory=Person))(_canpwn=ResetPassword)) | 1 | ResetPassword, MemberOf | Reverse |
| Who owns who? | (&(\|(objectCategory=Group)(objectCategory=Person))(_pwnable=Owns)) | 1 | Owns | Normal |

Remember, you might get too many results. Limit the selection of targets with (&(attribute=something)(_limit=10)) to just get 10 random targets (see LDAP queries below)

### Operational theory
*adalanche* works a bit differently than other tools, as it dumps everything it can from an Active Directory server, which it then saves to a highly compressed binary cache file for later use. This dump can be done by any unprivileged user, unless the Active Directory has been hardened to prevent this (almost no one does this).

The analysis phase is done on a cache file, so you do not have to be connected to the systems when doing analysis. This way you can explore different scenarios, and ask questions not easily answered otherwise.

### Analysis / Visualization
The tool works like an interactive map in your browser, and defaults to a ldap search query that shows you how to become "Domain Admin" or "Enterprise Admin" (i.e. member of said group or takeover of an account which is either a direct or indirect member of these groups.

### LDAP queries
The tool has its own LDAP query parser, and makes it easy to search for other objects to take over, by using a familiar search language.

**The queries support:**
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
- custom extensible match: length - matches on length of attribute values (member:count:>20 gives groups with more members than 20)
- synthetic attribute: _limit (_limit=10) returns true on the first 10 hits, false on the rest giving you a max output of 10 items
- synthetic attribute: _random100 (_random100<10) allows you to return a random percentage of results (&(objectclass=Person)(_random100<1)) gives you 1% of users
- synthetic attribute: _canpwn - allows you to select objects based on what they can pwn *directly* (&(objectclass=Group)(_canpwn=ResetPassword)) gives you all groups that are assigned the reset password right
- synthetic attribute: _pwnable - allows you to select objects based on how they can be pwned *directly* (&(objectclass=Person)(_pwnable=ResetPassword)) gives you all users that can have their password reset

## Current limitations
- A large AD with 500.000 objects results in a file approximately 250MB in size.
- adalanche IS A MEMORY HOG right now. Above AD will use up to 10GB RAM at times. RAM is cheap, getting pwned is not.
- There are probably mistakes, false positives and stuff I've overlooked. Feedback is welcome, but 

# Shoutouts
To everyone messing around with Active Directory - the team behind BloodHound, Will Schroeder @harmj0y, Sean Metcalf @PyroTek3, plus many others that I forgot. The MS API documentation kinda helped, and also other obscure places (stackoverflow lol) where I dug up technical stuff

## Happy hunting!

Feedback is welcome -> [@lkarlslund](https://twitter.com/lkarlslund)