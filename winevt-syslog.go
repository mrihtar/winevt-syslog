// Copyright (c) 2022 Matjaz Rihtar
package main

import (
  "flag"
  "fmt"
  syslog "github.com/RackSec/srslog"
  "github.com/gonutz/w32/v2"
  "log"
  "os"
  "os/signal"
  "path/filepath"
  "strings"
)

const (
  hdrRFC3164 = 1
  hdrRFC5424 = 2
  hdrUnix    = 3
  hdrDefault = 4
)
const (
  formCEF  = 1
  formLEEF = 2
)

var (
  exitChan   = make(chan os.Signal)
  errorsChan = make(chan error)
  out   *log.Logger
  sylog *syslog.Writer
  form  int
)

// Function GetExeVersion() extracts file version
// from this .exe file
//
func GetExeVersion(path string) string {
  size := w32.GetFileVersionInfoSize(path)
  if size <= 0 {
    return ""
  }
  info := make([]byte, size)
  rc := w32.GetFileVersionInfo(path, info)
  if !rc {
    return ""
  }
  fixed, rc := w32.VerQueryValueRoot(info)
  if !rc {
    return ""
  }
  version := fixed.FileVersion()
  ver := fmt.Sprintf("%d.%d.%d",
                     version & 0xFFFF000000000000 >> 48,
                     version & 0x0000FFFF00000000 >> 32,
                     version & 0x00000000FFFF0000 >> 16)
  return ver
} // func GetExeVersion

// Main function parses command line flags, opens connection to syslog server
// and registers for receiving Windows events. It then waits for events and
// calls custom callback function when an event is received.
//
func main() {
  // enable microseconds in log entries
  log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
  out = log.New(os.Stdout, log.Prefix(), log.Flags())

  // get this executable path
  thisfn, err := os.Executable()
  if err != nil {
    thisfn = os.Args[0]
  }
  logfn := strings.TrimSuffix(filepath.Base(thisfn), filepath.Ext(thisfn))
  exeVer := GetExeVersion(thisfn)
  out.Printf("Starting %v v%v\n", logfn, exeVer)

  // parse command line flags
  optProto := flag.String("proto", "udp", "Syslog protocol [udp, tcp]")
  optHost := flag.String("host", "127.0.0.1", "Syslog host name")
  optPort := flag.String("port", "514", "Syslog host port")
  optHeader := flag.String("header", "rfc3164", "Syslog header [rfc1364, rfc5424, unix, default]")
  optFormat := flag.String("format", "leef", "Syslog format [cef, leef]")
  flag.Parse()

  // check specified flags for invalid values
  switch *optProto {
    case "udp":
    case "tcp":
    default:
      log.Fatalf("Unknown syslog protocol: %v", *optProto)
  }
  hdr := hdrRFC3164
  switch *optHeader {
    case "rfc3164": hdr = hdrRFC3164
    case "rfc5424": hdr = hdrRFC5424
    case "unix":    hdr = hdrUnix
    case "default": hdr = hdrDefault
    default:
      log.Fatalf("Unknown syslog header: %v", *optHeader)
  }
  form = formCEF
  switch *optFormat {
    case "cef":  form = formCEF
    case "leef": form = formLEEF
    default:
      log.Fatalf("Unknown syslog format: %v", *optFormat)
  }

  // register exit/interrupt handler
  signal.Notify(exitChan, os.Interrupt)
  go HandleInterrupt()

  // connect to syslog server
  out.Printf("Connecting to syslog %s://%s:%s\n", *optProto, *optHost, *optPort)
  sylog, err = syslog.Dial(*optProto, *optHost + ":" + *optPort, syslog.LOG_AUTH | syslog.LOG_INFO, logfn)
  if err != nil {
    log.Fatalf("Failed to connect to syslog: %v", err)
  }
  defer sylog.Close()

  // specify syslog header format
  switch hdr {
    case 1: sylog.SetFormatter(syslog.RFC3164Formatter) // <prio>timestamp hostname tag[pid]: message
    case 2: sylog.SetFormatter(syslog.RFC5424Formatter) // <prio>1 timeRFC3339 hostname appname pid tag - message
    case 3: sylog.SetFormatter(syslog.UnixFormatter)    // <prio>timestamp tag[pid]: message
    case 4: sylog.SetFormatter(syslog.DefaultFormatter) // <prio> timeRFC3339 hostname tag[pid]: message
  }

  // Register for the following Windows events only:
  // Account logon and logon events
  // 4624  CL  An account was successfully logged on.
  // 4625  CL  An account failed to log on.
  // 4634  CL  An account was logged off.
  // 4647  CL  User initiated logoff.
  // 4648  CL  A logon was attempted using explicit credentials.
  // 4672  CL  Special privileges assigned to new logon.
  // 4768  DC  A Kerberos authentication ticket (TGT) was requested.
  // 4769  DC  A Kerberos service ticket was requested.
  // 4770  DC  A Kerberos service ticket was renewed.
  // 4771  DC  Kerberos pre-authentication failed.
  // 4776  DC  The computer attempted to validate the credentials for an account.
  // 4778  CL  A session was reconnected to a Window Station.
  // 4779  CL  A session was disconnected from a Window Station.
  // 4800  CL  The workstation was locked.
  // 4801  CL  The workstation was unlocked.

  out.Println("Subscribing to windows events")
  eventSubscription := &EventSubscription{
    channel:    "Security",
    query:      "*[System[EventID=4624] or System[EventID=4625] or System[EventID=4634] or System[EventID=4647] or System[EventID=4648] or System[EventID=4672] or System[EventID=4768] or System[EventID=4769] or System[EventID=4770] or System[EventID=4771] or System[EventID=4776] or System[EventID=4778] or System[EventID=4779] or System[EventID=4800] or System[EventID=4801]]",
    subsMethod: evtSubscribeToFutureEvents,
    errors:     errorsChan,
    callback:   EventCallback,
  }

  // check for errors
  if err := eventSubscription.Create(); err != nil {
    log.Fatalf("Failed to create event subscription: %v", err)
  }

  for err := range errorsChan {
    log.Printf("Event subscription error: %v", err)
  }

  // close the subscription
  if err := eventSubscription.Close(); err != nil {
    log.Fatalf("Encountered error while closing subscription: %v", err)
  } else {
    out.Println("Gracefully shutdown")
  }
} // func main

// Function HandleInterrupt() is called when an interrupt (^C, kill) is
// recevied
//
func HandleInterrupt() {
  <- exitChan
  out.Println("Interrupt received from terminal, cleaning up and closing")
  close(exitChan)
  close(errorsChan)
} // func HandleInterrupt

// Custom callback function, which is called when an event is recevied.
// It parses the event via specific function for this event and then
// sends the formatted message to syslog.
//
func EventCallback(event *Event) {
  var eventClassID, eventName string
  var sev int
  var hdr, msg string

  switch event.System.EventID {

    case "4624": // CL An account was successfully logged on.
      eventClassID = "CL Logon"
      eventName = "Account logged on"
      sev = 2
      msg = Event4624(event)

    case "4625": // CL An account failed to log on.
      eventClassID = "CL Logon"
      eventName = "Account failed logon"
      sev = 3
      msg = Event4625(event)

    case "4634": // CL An account was logged off.
      eventClassID = "CL Logon"
      eventName = "Account logged off"
      sev = 2
      msg = Event4634(event)

    case "4647": // CL User initiated logoff.
      eventClassID = "CL Logon"
      eventName = "User initiated logoff"
      sev = 2
      msg = Event4647(event)

    case "4648": // CL A logon was attempted using explicit credentials.
      eventClassID = "CL Logon"
      eventName = "Logon using explicit credentials"
      sev = 2
      msg = Event4648(event)

    case "4672": // CL Special privileges assigned to new logon.
      eventClassID = "CL Logon"
      eventName = "Privileges assigned to logon"
      sev = 3
      msg = Event4672(event)

    case "4768": // DC A Kerberos authentication ticket (TGT) was requested.
      eventClassID = "DC Logon"
      eventName = "Kerberos authentication ticket requested"
      sev = 2
      msg = Event4768(event)

    case "4769": // DC A Kerberos service ticket was requested.
      eventClassID = "DC Logon"
      eventName = "Kerberos service ticket requested"
      sev = 2
      msg = Event4769(event)

    case "4770": // DC A Kerberos service ticket was renewed.
      eventClassID = "DC Logon"
      eventName = "Kerberos service ticket renewed"
      sev = 2
      msg = Event4770(event)
 
    case "4771": // DC Kerberos pre-authentication failed.
      eventClassID = "DC Logon"
      eventName = "Kerberos pre-authentication failed"
      sev = 3
      msg = Event4771(event)

    case "4776": // DC The computer attempted to validate the credentials for an account.
      eventClassID = "DC Logon"
      eventName = "Computer attempted credential validation"
      sev = 2
      msg = Event4776(event)
 
    case "4778": // CL A session was reconnected to a Window Station.
      eventClassID = "CL Logon"
      eventName = "Session reconnected to Window Station"
      sev = 2
      msg = Event4778(event)

    case "4779": // CL A session was disconnected from a Window Station.
      eventClassID = "CL Logon"
      eventName = "Session disconnected from Window Station"
      sev = 2
      msg = Event4779(event)

    case "4800": // CL The workstation was locked.
      eventClassID = "CL Logon"
      eventName = "Workstation was locked"
      sev = 2
      msg = Event4800(event)

    case "4801": // CL The workstation was unlocked.
      eventClassID = "CL Logon"
      eventName = "Workstation was unlocked"
      sev = 2
      msg = Event4801(event)

    default:
      eventClassID = "Unknown"
      eventName = "Unknown event"
      sev = 2
      msg = fmt.Sprintf("Event=%v", event.System.EventID)
  }

  // specify syslog message format
  if form == formCEF {
    hdr = fmt.Sprintf("CEF:0|Microsoft|Events|1.0|%v|%v|%v|", eventClassID, eventName, sev)
  } else { // formLEEF
    hdr = fmt.Sprintf("LEEF:1.0|Microsoft|Events|1.0|%v|cat=%v\tsev=%v\t", eventName, eventClassID, sev)
  }

  out.Println(hdr + msg)
  sylog.Info(hdr + msg)
} // func EventCallback
