---
title: "Recommended SentinelOne Custom Detections"
date: 2021-04-15T19:16:38-05:00
draft: false

# HelloFriend Specific
#hideReadMore: false
#cover = "img/default.jpg"
#description = "description"
---

## Deep Visibility
SentinelOne Deep Visibility has a very powerful language for querying on nearly any endpoint activity you'd want to dig up. I've been using the Watchlist feature very heavily; from detecting common phishing Url patterns, unapproved software, insider threats, to LOLBAS activity. But very soon the Watchlist feature will be superseded by Custom Detections, basically Watchlist with ranking and remediation options.

The purpose of this post is to document a few top priority queries that go beyond the granular queries I've created and shared before. The queries shared here will attempt to cover a number of sub-techniques within a single query to reduce the number of saved queries required in the console. This may result in some possibly crazy looking queries but I've attempted to format them in a logical manner that you can take from them what you will.

_I must note that I write a lot of these queries late at night, console up on one monitor and a VM for executing Atomic Red Team up on another. With that said, there may be a few copy/paste or format mistakes, but I'm treating this as a live document and will maintain it for a few months._

## Tactics and Techniques

Below I have compiled 8 techniques covering more than 12 sub-techniques (12 queries total), and attempted to document the sub-techniques covered and purpose of the queries. The goal was to add to or fill gaps with SentinelOne detections.

_I'm aware that the theme for this site changes code blocks to full caps, but copy/paste formatting should be the same. If you experience otherwise please copy these queries from the [markdown copy](https://github.com/keyboardcrunch/keyboardcrunch.github.io/blob/master/content/posts/Recommended-SentinelOne-Custom-Detections.md)._

* [T1003 OS Credential Dumping](#t1003-os-credential-dumping)
* [T1053 Scheduled Task/Job](#t1053-scheduled-taskjob)
* [T1562 Impair Defenses](#t1562-impair-defenses)
* [T1059 Command and Scripting Interpreter](#t1059-command-and-scripting-interpreter)
* [T1218 Signed Binary Proxy Execution](#t1218-signed-binary-proxy-execution)
* [T1482 Domain Trust Discovery](#t1482-domain-trust-discovery)
* [T1548.002 Abuse Elevation Control Mechanism](#t1548002-abuse-elevation-control-mechanism)
* [T1027.004 Compile After Delivery](#t1027004-compile-after-delivery)




### T1003 OS Credential Dumping
**Tactic:**  Credential Access 

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1003/](https://attack.mitre.org/techniques/T1003/)

**Sub-Techniques:** T1003.001 LSASS Memory, T1003.003 NTDS

**Description:** Credential theft being the ultimate goal before moving on to lateral movement, the below sub-techniques are commonly observed by actors and go beyond the general detections.

**Query:**
```
( TgtProcImageSha1 = "f0c52cea19c204f5cdbe952cc7cfc182e20d8d43" OR TgtProcCmdline ContainsCIS "-ma lsass.exe" OR TgtProcCmdline RegExp "(?i)comsvcs.dl.*(minidump)" OR TgtFilePath = "C:\Windows\Temp\dumpert.dmp" OR TgtFilePath RegExp "^.*lsass.*.DMP" OR (SrcProcCmdline ContainsCIS "sekurlsa::minidump" OR SrcProcCmdline ContainsCIS "sekurlsa::logonpasswords") OR SrcProcCmdline ContainsCIS "live lsa" )
OR
( SrcProcCmdline RegExp "^.*copy.*\\Windows\\NTDS\\NTDS.dit.*" OR SrcProcCmdline RegExp "^.*copy.*\\Windows\\System32\\config\\SYSTEM .*" OR SrcProcCmdline ContainsCIS "save HKLM\SYSTEM" OR (TgtProcName = "ntdsutil.exe" AND TgtProcCmdline ContainsCIS "ac i ntds") )
```



### T1053 Scheduled Task/Job
**Tactic:**  Execution, Persistence, Privilege Escalation 

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1053/](https://attack.mitre.org/techniques/T1053/)

**Sub-Techniques:** T1053.002 Windows AT, T1053.005 Scheduled Task

**Description:** Common in the persistence stage of attacks is the scheduling of tasks. Combined into a single query is the detection of the two most common sub-techniques, AT command and scheduled tasks.

**Query:**
```
( TgtProcName = "at.exe" AND TgtProcCmdLine ContainsCIS "/interactive " )
OR
( ( ( TgtProcName = "schtasks.exe" AND TgtProcCmdLine ContainsCIS "/create" ) OR ( SrcProcCmdLine ContainsCIS "New-ScheduledTask" OR SrcProcCmdScript  ContainsCIS "New-ScheduledTask" ) ) AND SrcProcParentName Not In ("services.exe", "OfficeClickToRun.exe" ) AND ObjectType != "cross_process" )
```



### T1562 Impair Defenses
**Tactic:** Defense Evasion

**Platforms:** Windows, Linux

**Reference:** [https://attack.mitre.org/techniques/T1562/](https://attack.mitre.org/techniques/T1562/)

**Description:** It's not uncommon for attackers to take actions to blind defenders and one of the easiest and most common is to disable system logging, turning off the firewall, or disabling Windows security features. Below I've broken out three queries that focus on detecting those attacks, and each of those queries is broken up logically by OR statements that could be used separately. Threre are so many detections to be built out for T1562, especially [T1562.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1562.001/T1562.001.md) That I recommend you dig deeper into this.

#### T1562.001 Disable Logging
**Description:** In order, this script detects the disabling of Syslog and two methods of disabling Sysmon logging.
```
( TgtProcName In Contains ( "service", "chkconfig", "systemctl" ) AND TgtProcCmdLine In Contains ( "rsyslog stop", "off rsyslog", "stop rsyslog", "disable rsyslog" ) )
OR
( TgtProcName = "fltmc.exe" AND TgtProcCmdLine ContainsCIS "unload SysmonDrv" )
OR
( TgtProcName = "sysmon.exe" AND TgtProcCmdLine ContainsCIS "-u" )
```

#### T1562.001 Disable Security
**Description:** The below query will detect disabling of AMSI providers or the disabling of Excel security features.
```
( RegistryPath ContainsCIS "\Microsoft\AMSI\Providers" AND EventType In ( "Registry Key Delete", "Registry Value Delete" ) )
OR
( RegistryKeyPath ContainsCIS "Excel\Security" OR RegistryKeyPath ContainsCIS "Excel\Security\ProtectedView") AND RegistryKeyPath In Contains Anycase ( "VBAWarnings","DisableInternetFilesInPV","DisableUnsafeLocationsInPV","DisableAttachementsInPV" ) AND EventType In ( "Registry Value Create","Registry Value Modified" ) )
```

#### T1562.004 Tamper with Firewall
**Description:** In order, the below query will detect the disable of the Windows firewall followed by methods for disabling the Linux firewall.
```
( TgtProcName = "netsh.exe" AND TgtProcCmdLine ContainsCIS "state off" )
OR
( SrcProcName In Contains ("service","chkconfig") AND SrcProcCmdLine In Contains ("off","stop") AND SrcProcCmdLine ContainsCIS "tables") OR (TgtProcName = "systemctl" AND TgtProcCmdLine In Contains ("stop","disable") AND TgtProcCmdLine Contains "firewalld" )
```



### T1059 Command and Scripting Interpreter
**Tactic:** Execution

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1059/](https://attack.mitre.org/techniques/T1059/)

**Description:** Attackers often abuse the command and script interpreters already present on systems to execute malicious code. For relevance and fidelity I've broken detections out into detecting two different common methods, execution of scripts from temp directories and Powershell download cradles.

#### T1059.001 Powershell Download Cradles
**Description:** There are many methods for initiating a file download with Powershell, and a few obscure ways of executing Powershell, so here we're focusing on the command strings for detection.

```
ProcessCmd In Contains Anycase  ( "Net.WebClient", "(iwr", "DownloadString(", "WinHttp.WinHttpRequest"  , "IEX ", "| IEX", "InternetExplorer.Application", "Msxml2.XMLHTTP", "DownloadString(" )
```

#### T1059 Execution from Temp Directories
**Sub-Techniques:** T1059.003 Windows Command Shell, T1059.005 Visual Basic

**Description:** The below will detect either cscript or cmd executing a bat or vbs from any Temp directory, regardless of case.

```
SrcProcName In ( "cscript.exe", "cmd.exe" ) AND SrcProcCmdLine RegExp "(?i)\bTemp\b.*\.(bat|vbs)" AND SrcProcParentName != "msiexec.exe"
```



### T1218 Signed Binary Proxy Execution
**Tactic:** Execution

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1218/](https://attack.mitre.org/techniques/T1218/)

**Description:**
Signed binary proxy execution is a method for bypassing standard defenses through execution of malicious content by signed binaries. I've decided to build these out as two queries, focusing on execution of scripts and remote content, because the other sub-techniques are require a lot of environment specific tuning.

#### T1218 Script Execution
**Sub-Techniques:** T1218.005 Mshta, T1218.011 Rundll32
```
SrcProcName In ( "mshta.exe", "rundll32.exe" ) and SrcProcCmdLine In Contains Anycase ( "javascript:", "vbscript:", "wscript.shell", "env:appdata", "script:", "mshtml,RunHTMLApplication" )
```

#### T1218 with Remote Payload
**Sub-Techniques:** T1218.001 Compiled HTML, T1218.005 Mshta, T1218.007, T1218.010 Regsvr32, T1218.011 Rundll32

**Description:** The below query will detect execution of payloads with remote content (urls) in the command line.

**Query:**
```
SrcProcName In( "mshta.exe", "hh.exe", "regsvr32.exe", "rundll32.exe", "msiexec.exe" ) AND SrcProcCmdLine RegExp "https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&\/\/=]*)"
```



### T1482 Domain Trust Discovery
**Tactic:** Discovery

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1482/](https://attack.mitre.org/techniques/T1482/)

**Description:**
The below query will detect domain trust enumeration/discovery through the execution of Nltest, dsquery, AdFind, and Powershell AD modules (in order).

**Query:**
```
( TgtProcName = "nltest.exe" AND ( TgtProcCmdLine ContainsCIS "domain_trusts" OR TgtProcCmdLine ContainsCIS "all_trusts" OR TgtProcCmdLine ContainsCIS "dclist" ))
OR
( TgtFileInternalName ContainsCIS "AdFind" AND ( TgtProcCmdLine ContainsCIS "trustdmp" OR TgtProcCmdLine ContainsCIS "-f \"(objectcategory=") )
OR
( ProcessCmd ContainsCIS "Get-NetForestTrust" OR ProcessCmd ContainsCIS "Get-NetDomainTrust" )
```



### T1548.002 Abuse Elevation Control Mechanism
**Tactic:** Privilege Escalation, Defense Evasion

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1548/](https://attack.mitre.org/techniques/T1548/)

**Description:** Elevation control mechanisms such as Windows UAC are often abused to elevate privileges. The below query will detect a few of these techniques, though the methods of UAC bypass are consistently expanding.

**Query:**
```
( SrcProcCmdLine ContainsCIS "\shell\open\command" AND SrcProcCmdLine RegExp "(?i).*(cmd.exe|fodhelper.exe|ComputerDefaults.exe|sdclt.exe)" AND ObjectType = "process" ) OR ( SrcProcCmdLine ContainsCIS "C:\Windows \S" AND ObjectType != "registry" )
```



### T1027.004 Compile After Delivery
**Tactic:** Defense Evasion

**Platforms:** Windows

**Reference:** [https://attack.mitre.org/techniques/T1027/004/](https://attack.mitre.org/techniques/T1027/004/)

**Description:** Transfer and compilation of source code is often the easiest way to bypass over-the-wire detections as well as reducing detections. The below query will detect execution by csc or msbuild, limited by compilation with either target or output arguments.

**Query:**
```
SrcProcName In ( "csc.exe", "msbuild.exe" ) AND TgtFileIsExecutable IS TRUE AND ( SrcProcCmdLine RegExp "(?i).*\/t.*:.*" OR SrcProcCmdLine RegExp "(?i).*\/o.*:.*exe" )
```