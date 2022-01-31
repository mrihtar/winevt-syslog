// Copyright (c) 2017 Liam Haworth
// Copyright (c) 2022 Matjaz Rihtar
package main

import "C"
import (
  "encoding/xml"
  "fmt"
  "golang.org/x/sys/windows"
  "syscall"
  "unsafe"
)

// Main Windows Event structure containing Windows Event
// parsed from rendered XML response
//
type Event struct {
  XMLName   xml.Name     `xml:"Event"`
  System    *System      `xml:"System"`
  EventData []*EventData `xml:"EventData>Data"`
} // struct Event

// System part of main Windows Event structure
//
type System struct {
  Provider      struct {
    Name              string `xml:"Name,attr"`
    Guid              string `xml:"Guid,attr"`
    EventSourceName   string `xml:"EventSourceName,attr"`
  } `xml:"Provider"`
  EventID       string `xml:"EventID"`
  Version       string `xml:"Version"`
  Level         string `xml:"Level"`
  Task          string `xml:"Task"`
  Opcode        string `xml:"Opcode"`
  Keywords      string `xml:"Keywords"`
  TimeCreated   struct {
    SystemTime        string `xml:"SystemTime,attr"`
  } `xml:"TimeCreated"`
  EventRecordID string `xml:"EventRecordID"`
  Correlation   struct {
    ActivityID        string `xml:"ActivityID,attr"`
    RelatedActivityID string `xml:"RelatedActivityID,attr"`
  } `xml:"Correlation"`
  Execution     struct {
    ProcessID         string `xml:"ProcessID,attr"`
    ThreadID          string `xml:"ThreadID,attr"`
    ProcessorID       string `xml:"ProcessorID,attr"`
    SessionID         string `xml:"SessionID,attr"`
    KernelTime        string `xml:"KernelTime,attr"`
    UserTime          string `xml:"UserTime,attr"`
    ProcessorTime     string `xml:"ProcessorTime,attr"`
  } `xml:"Execution"`
  Channel       string `xml:"Channel"`
  Computer      string `xml:"Computer"`
  Container     string `xml:"Container"`
  Security      struct {
    UserID            string `xml:"UserID,attr"`
  } `xml:"Security"`
} // struct System

// EventData part of main Windows Event structure
//
type EventData struct {
  Key   string `xml:"Name,attr"`
  Value string `xml:",chardata"`
} // struct EventData

const (
  evtSubscribeToFutureEvents      = 1
  evtSubscribeStartAtOldestRecord = 2
  evtSubscribeActionError   = 0
  evtSubscribeActionDeliver = 1
  evtRenderEventXML = 1
)

var (
  // Load Windows Event API library and functions
  modwevtapi       = windows.NewLazySystemDLL("wevtapi.dll")
  procEvtSubscribe = modwevtapi.NewProc("EvtSubscribe")
  procEvtRender    = modwevtapi.NewProc("EvtRender")
  procEvtClose     = modwevtapi.NewProc("EvtClose")
)

// Windows Event callback function template
type Callback func(event *Event)

// Event subscription structure for subscribing to Windows Events
type EventSubscription struct {
  channel    string
  query      string
  subsMethod int
  errors     chan error
  callback   Callback

  winAPIHandle windows.Handle
} // struct EventSubscription

// Function Create() subscribes for receiving events via Eventlog
// with specified channel and query in structure EventSubscription
//
func (evtSubs *EventSubscription) Create() error {
  if evtSubs.winAPIHandle != 0 {
    return fmt.Errorf("windows_events: subscription already created in kernel")
  }

  winChannel, err := windows.UTF16PtrFromString(evtSubs.channel)
  if err != nil {
    return fmt.Errorf("windows_events: bad channel name: %s", err)
  }

  winQuery, err := windows.UTF16PtrFromString(evtSubs.query)
  if err != nil {
    return fmt.Errorf("windows_events: bad query string: %s", err)
  }

  // subscribe to events
  handle, _, err := procEvtSubscribe.Call(
    0,
    0,
    uintptr(unsafe.Pointer(winChannel)),
    uintptr(unsafe.Pointer(winQuery)),
    0,
    0,
    syscall.NewCallback(evtSubs.WinAPICallback), // callback function
    uintptr(evtSubs.subsMethod),
  )

  if handle == 0 {
    return fmt.Errorf("windows_events: failed to subscribe to events: %s", err)
  }

  evtSubs.winAPIHandle = windows.Handle(handle)
  return nil
} // func Create

// Function Close() unsubscribes from receiving events via Eventlog
// and closes subscription handle
//
func (evtSubs *EventSubscription) Close() error {
  if evtSubs.winAPIHandle == 0 {
    return fmt.Errorf("windows_events: no subscription to close")
  }

  if returnCode, _, err := procEvtClose.Call(uintptr(evtSubs.winAPIHandle)); returnCode == 0 {
    return fmt.Errorf("windows_events: encountered error while closing event subscription handle: %s", err)
  }

  evtSubs.winAPIHandle = 0
  return nil
} // func Close

// Function WinAPICallback() receives the call from Windows kernel when an
// event matching the query and channel is received. Received event is
// rendered as an XML string, which is then unmarshaled into the main Event
// structure. With this parsed data the custom callback is invoked.
//
func (evtSubs *EventSubscription) WinAPICallback(action, userContext, event uintptr) uintptr {
  switch action {
    case evtSubscribeActionError:
      evtSubs.errors <- fmt.Errorf("windows_events: encountered error during callback: Win32 Error %x", uint16(event))

    case evtSubscribeActionDeliver:
      renderSpace := make([]uint16, 4096)
      bufferUsed := uint16(0)
      propertyCount := uint16(0)

      // render received event data
      returnCode, _, err := procEvtRender.Call(
        0,
        event,
        evtRenderEventXML,
        4096,
        uintptr(unsafe.Pointer(&renderSpace[0])),
        uintptr(unsafe.Pointer(&bufferUsed)),
        uintptr(unsafe.Pointer(&propertyCount)),
      )

      if returnCode == 0 {
        evtSubs.errors <- fmt.Errorf("windows_event: failed to render event data: %s", err)
      } else {
        // parse received event data
        dataParsed := new(Event)
        err := xml.Unmarshal([]byte(windows.UTF16ToString(renderSpace)), dataParsed)

        if err != nil {
          evtSubs.errors <- fmt.Errorf("windows_event: failed to unmarshal event xml: %s", err)
        } else {
          // call custom callback
          evtSubs.callback(dataParsed)
        }
      }

    default:
      evtSubs.errors <- fmt.Errorf("windows_events: encountered error during callback: unsupported action code %x", uint16(action))
  } // switch

  return 0
} // func WinAPICallback

// Function FindEventData() loops through EventData slice to find the
// first EventData entry with a matching key
// If the key is not found, an empty string is returned.
// 
func (event *Event) FindEventData(key string) string {
  for _, ed := range event.EventData {
    if ed.Key == key {
      return ed.Value
    }
  }
  return "" // nil
} // func FindEventData
