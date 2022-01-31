# winevt-syslog

Winevt-syslog forwards specific events (currently logon related events) as
syslog messages to syslog server.<br>
It's written in Go language and uses a modified version of [Liam Haworth's Windows events]
and [RackSec's Srslog].

## Principle of operation

Winevt-syslog first opens a connection to syslog server (udp or tcp), subscribes
to Windows events and hibernates. When the subscribed event arrives, it wakes up,
process received event in a callback and sends it to syslog server.

Currently, the following logon related events are intercepted:
- 4624  (client)  An account was successfully logged on.
- 4625  (client)  An account failed to log on.
- 4634  (client)  An account was logged off.
- 4647  (client)  User initiated logoff.
- 4648  (client)  A logon was attempted using explicit credentials.
- 4672  (client)  Special privileges assigned to new logon.
- 4768  (DC)      A Kerberos authentication ticket (TGT) was requested.
- 4769  (DC)      A Kerberos service ticket was requested.
- 4770  (DC)      A Kerberos service ticket was renewed.
- 4771  (DC)      Kerberos pre-authentication failed.
- 4776  (DC)      The computer attempted to validate the credentials for an account.
- 4778  (client)  A session was reconnected to a Window Station.
- 4779  (client)  A session was disconnected from a Window Station.

To change this list, you have to change the query string in the program and
recompile it.

## Compilation

<pre>
$ go get -u
$ go mod tidy -v
$ go build
</pre>
Before build you can use go-winres to generate resources (icon, version
information) to be included in the final .exe:
<pre>
$ go install github.com/tc-hib/go-winres@latest
$ go-winres make
$ go build
</pre>
<sup>EventLog icon copyright &copy; Microsoft.</sup>

## Usage

Winevt-syslog can be run from command line or as a service.
Possible command line options for both are:
<pre>
$ winevt-syslog.exe
Usage of winevt-syslog.exe:
  -format string
        Syslog format [cef, leef] (default "cef")
  -header string
        Syslog header [rfc1364, rfc5424, unix, default] (default "rfc3164")
  -host string
        Syslog host name (default "127.0.0.1")
  -port string
        Syslog host port (default "514")
  -proto string
        Syslog protocol [udp, tcp] (default "udp")
</pre>

### Running from command line

<pre>
$ winevt-syslog.exe
2022/01/31 14:06:51.360360 Starting winevt-syslog v1.2.1
2022/01/31 14:06:51.360360 Connecting to syslog udp://127.0.0.1:514
2022/01/31 14:06:51.361900 Subscribing to windows events
</pre>

### Running as a service

To run winevt-syslog.exe as a service, you have to use additional program
[Windows Service Wrapper], which is available on https://github.com/winsw/winsw .
Download the latest version of WinSW*.exe, rename it as `winevt-service.exe` and
copy it to this directory.

Winevt-service.exe needs configuration file `winevt-service.xml` (sample already
supplied), where you specify command line and other parameters for Winevt Syslog
program/service.

Winevt Syslog service needs to be installed first and then started:
<pre>
$ winevt-service install
$ winevt-service start
</pre>
Other commands: status, restart, stop, uninstall, ...

Winevt Syslog service is currently configured (see `winevt-service.xml`) to
store output from winevt-syslog.exe in local files `winevt-service.out.log`
and `winevt-service.err.log`, which are rotated, if they grow too big.

## Syslog formats

Syslog servers expect syslog messages in format:
<br>
<strong>&lt;syslog_header&gt;&lt;syslog_message&gt;</strong>
<br><br>
Syslog header can be in one of the following formats:

- **RFC1364**  
  **`<prio>timestamp hostname tag[pid]: message`**<br>
  Timestamp looks like this: Mon dd HH:MM:SS<br>
  Example:<br>
  `<38>Jan 31 14:41:09 chihuahua winevt-syslog[17356]: CEF:0|...`

- **RFC5424**  
  **`<prio>1 timeRFC3339 hostname appname pid tag - message`**<br>
  Time in [RFC3339] (ISO 8601) format looks like this: YYYY-MM-DDTHH:MM:SS+HH:MM<br>
  Example:<br>
  `<38>1 2022-01-31T14:41:09+01:00 chihuahua winevt-syslog.exe 17356 winevt-syslog - CEF:0|...`

- **Unix**  
  **`<prio>timestamp tag[pid]: message`**<br>
  Example:<br>
  `<38>Jan 31 14:41:09 winevt-syslog[17356]: CEF:0|...`

- **Default**  
  **`<prio> timeRFC3339 hostname tag[pid]: message`**<br>
  Example:<br>
  `<38> 2022-01-31T14:41:09+01:00 chihuahua winevt-syslog[17356]: CEF:0|...`

Syslog message can be in one of the following formats:

- **CEF**  
  **`CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension [msg=...]`**<br>
  Version is always 0.<br>
  Extension has the following format:<br>
  **`key=value<tab>key=value<tab>key=value<tab>key=value...`**<br>
  Example:<br>
  `CEF:0|Microsoft|Events|1.0|CL Logon|Logon using explicit credentials|2|Event=4648 SubjectUserSid=S-1-5-18 ...`

- **LEEF**  
  **`LEEF:Version|Vendor|Product|Version|EventID|Extension [msg=...]`**<br>
  Version can be 1.0 or 2.0, but since the only difference is delimiter character,
  we use only version 1.0, where the delimiter character is &lt;tab&gt;.<br>
  Extension has the following format:<br>
  **`key=value<tab>key=value<tab>key=value<tab>key=value...`**<br>
  Example:<br>
  `LEEF:1.0|Microsoft|Events|1.0|CL Logon|Event=4648 SubjectUserSid=S-1-5-18 ...`

## Reference

- [Microsoft Event Schema (Microsoft)]
- [Windows 10 and Windows Server 2016 Security Auditing and Monitoring Reference (Microsoft)]
- [Windows Event Log Analysis (Forward Defense)]
- [Common Event Format (CEF) Rev. 16 (ArcSight)]
- [Log Event Extended Format (LEEF) (IBM QRadar)]

[Liam Haworth's Windows events]: https://github.com/LiamHaworth/windows-events
[RackSec's Srslog]: https://github.com/RackSec/srslog
[RFC3339]: https://datatracker.ietf.org/doc/html/rfc3339
[Windows Service Wrapper]: https://github.com/winsw/winsw
[Common Event Format (CEF) Rev. 16 (ArcSight)]: https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf
[Microsoft Event Schema (Microsoft)]: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-even6/8c61aef7-bd4b-4edb-8dfd-3c9a7537886b
[Windows Event Log Analysis (Forward Defense)]: https://forwarddefense.com/media/attachments/2021/05/15/windows-event-log-analyst-reference.pdf
[Log Event Extended Format (LEEF) (IBM QRadar)]: https://www.ibm.com/support/knowledgecenter/en/SS42VS_DSM/com.ibm.dsm.doc/b_Leef_format_guide.pdf?origURL=SS42VS_DSM/b_Leef_format_guide.pdf
[Windows 10 and Windows Server 2016 Security Auditing and Monitoring Reference (Microsoft)]: https://download.microsoft.com/download/7/9/F/79F3E0B9-4A00-4D15-9953-045BC9BE9338/Windows%2010%20and%20Windows%20Server%202016%20Security%20Auditing%20and%20Monitoring%20Reference.docx
