// Copyright (c) 2022 Matjaz Rihtar
package main

import (
  "fmt"
  "strings"
  "strconv"
)

// Converts LogonType number to descriptive string
//
func ConvertLogonType(logonType string) string {
  var lt int64; var err error
  if lt, err = strconv.ParseInt(logonType, 0, 64); err != nil {
    lt = -1
  }
  switch lt {
    case  2: logonType = "Interactive"
    case  3: logonType = "Network"
    case  4: logonType = "Batch"
    case  5: logonType = "Service"
    case  7: logonType = "Unlock"
    case  8: logonType = "NetworkCleartext"
    case  9: logonType = "NewCredentials"
    case 10: logonType = "RemoteInteractive"
    case 11: logonType = "CachedInteractive"
    default: // Unknown
  }
  return logonType
} // func ConvertLogonType

// Converts Kerberos return code number to descriptive string
//
func ConvertKerberosStatus(status string) string {
  var rc int64; var err error
  if rc, err = strconv.ParseInt(status, 0, 64); err != nil {
    rc = -1
  }
  switch rc {
    case 0x00: status = "No error"
    case 0x01: status = "Client's entry in KDC database has expired"
    case 0x02: status = "Server's entry in KDC database has expired"
    case 0x03: status = "Requested Kerberos version number not supported"
    case 0x04: status = "Client's key encrypted in old master key"
    case 0x05: status = "Server's key encrypted in old master key"
    case 0x06: status = "Client not found in Kerberos datab"
    case 0x07: status = "Server not found in Kerberos database"
    case 0x08: status = "Multiple principal entries in KDC database"
    case 0x09: status = "The client or server has a null key (master key)"
    case 0x0a: status = "Ticket (TGT) not eligible for postdating"
    case 0x0b: status = "Requested start time is later than end time"
    case 0x0c: status = "KDC policy rejects request"
    case 0x0d: status = "KDC cannot accommodate requested option"
    case 0x0e: status = "KDC has no support for encryption type"
    case 0x0f: status = "KDC has no support for checksum type"
    case 0x10: status = "KDC has no support for PADATA type (pre-authentication data)"
    case 0x11: status = "KDC has no support for transited type"
    case 0x12: status = "Client's credentials have been revoked"
    case 0x13: status = "Credentials for server have been revoked"
    case 0x14: status = "TGT has been revoked"
    case 0x15: status = "Client not yet valid - try again later"
    case 0x16: status = "Server not yet valid - try again later"
    case 0x17: status = "Password has expired - hange password to reset"
    case 0x18: status = "Pre-authentication information was invalid"
    case 0x19: status = "Additional pre-authentication required"
    case 0x1a: status = "KDC does not know about the requested server"
    case 0x1b: status = "KDC is unavailable"
    case 0x1f: status = "Integrity check on decrypted field failed"
    case 0x20: status = "Integrity check on decrypted field failed"
    case 0x21: status = "The ticket is not yet valid"
    case 0x22: status = "The request is a replay"
    case 0x23: status = "The ticket is not for us"
    case 0x24: status = "The ticket and authenticator do not match"
    case 0x25: status = "The clock skew is too great"
    case 0x26: status = "Network address in network layer header doesn't match address inside ticket"
    case 0x27: status = "Protocol version numbers don't match (PVNO)"
    case 0x28: status = "Message type is unsupported"
    case 0x29: status = "Message stream modified and checksum didn't match"
    case 0x2a: status = "Message out of order (possible tampering)"
    case 0x2c: status = "Specified version of key is not available"
    case 0x2d: status = "Service key not available"
    case 0x2e: status = "Mutual authentication failed"
    case 0x2f: status = "Incorrect message direction"
    case 0x30: status = "Alternative authentication method required"
    case 0x31: status = "Incorrect sequence number in message"
    case 0x32: status = "Inappropriate type of checksum in message (checksum may be unsupported)"
    case 0x33: status = "Desired path is unreachable"
    case 0x34: status = "Too much data"
    case 0x3c: status = "Generic error"
    case 0x3d: status = "Field is too long for this implementation"
    case 0x3e: status = "The client trust failed or is not implemented"
    case 0x3f: status = "The KDC server trust failed or could not be verified"
    case 0x40: status = "The signature is invalid"
    case 0x41: status = "A higher encryption level is needed"
    case 0x42: status = "User-to-user authorization is required"
    case 0x43: status = "No TGT was presented or available"
    case 0x44: status = "Incorrect domain or principal"
    default: // Unknown
  }
  return status
} // func ConvertKerberosStatus

// Converts Ticket Encryption type number to descriptive string
//
func ConvertTicketEncryptionType(ticketEncryptionType string) string {
  var tet int64; var err error
  if tet, err = strconv.ParseInt(ticketEncryptionType, 0, 64); err != nil {
    tet = -1
  }
  switch tet {
    case 0x01: ticketEncryptionType = "DES-CBC-CRC"
    case 0x03: ticketEncryptionType = "DES-CBC-MD5"
    case 0x11: ticketEncryptionType = "AES128-CTS-HMAC-SHA1-96"
    case 0x12: ticketEncryptionType = "AES256-CTS-HMAC-SHA1-96"
    case 0x17: ticketEncryptionType = "RC4-HMAC"
    case 0x18: ticketEncryptionType = "RC4-HMAC-EXP"
    default: // Unknown
  }
  return ticketEncryptionType
} // func ConvertTicketEncryptionType

// Converts Pre-Auth Type number to descriptive string
//
func ConvertPreAuthType(preAuthType string) string {
  var pet int64; var err error
  if pet, err = strconv.ParseInt(preAuthType, 0, 64); err != nil {
    pet = -1
  }
  switch pet {
    case   0: preAuthType = "NO-PA"
    case   2: preAuthType = "PA-ENC-TIMESTAMP"
    case  11: preAuthType = "PA-ETYPE-INFO"
    case  15: preAuthType = "PA-PK-AS-REP_OLD"
    case  17: preAuthType = "PA-PK-AS-REP"
    case  19: preAuthType = "PA-ETYPE-INFO2"
    case  20: preAuthType = "PA-SVR-REFERRAL-INFO"
    case 138: preAuthType = "PA-ENCRYPTED-CHALLENGE"
    default: // Unknown
  }
  return preAuthType
} // func ConvertPreAuthType

// Converts Microsoft Authorization error code number to descriptive string
//
func ConvertMicrosoftAuthStatus(status string) string {
  var ec int64; var err error
  if ec, err = strconv.ParseInt(status, 0, 64); err != nil {
    ec = -1
  }
  switch ec {
    case 0x00000000: status = "No errors"
    case 0xc0000064: status = "The username does not exist (bad username)"
    case 0xc000006a: status = "Account logon with misspelled or bad password"
    case 0xc000006d: status = "Generic logon failure"
    case 0xc000006f: status = "Account logon outside authorized hours"
    case 0xc0000070: status = "Account logon from unauthorized workstation"
    case 0xc0000071: status = "Account logon with expired password"
    case 0xc0000072: status = "Account logon to account disabled by administrator"
    case 0xc0000193: status = "Account logon with expired account"
    case 0xc0000224: status = "Account logon with Change Password at Next Logon flagged"
    case 0xc0000234: status = "Account logon with account locked"
    case 0xc0000371: status = "The local account store does not contain secret material for the specified account"
    default: // Unknown
  }
  return status
} // func ConvertMicrosoftAuthStatus

// ----------------------------------------------------------------------------
// Event 4624  CL  An account was successfully logged on.
//
func Event4624(event *Event) string {
  targetUserSid := event.FindEventData("TargetUserSid")
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetLogonId := event.FindEventData("TargetLogonId")
  subjectUserSid := event.FindEventData("SubjectUserSid")
  subjectUserName := event.FindEventData("SubjectUserName")
  subjectDomainName := event.FindEventData("SubjectDomainName")
  subjectLogonId := event.FindEventData("SubjectLogonId")
  logonType := event.FindEventData("LogonType")
  logonProcessName := event.FindEventData("LogonProcessName")
  authenticationPackageName := event.FindEventData("AuthenticationPackageName")
  workstationName := event.FindEventData("WorkstationName")
  logonGuid := event.FindEventData("LogonGuid")
  processName := event.FindEventData("ProcessName")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")

  logonType = ConvertLogonType(logonType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserSid=%v", targetUserSid)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetLogonId=%v", targetLogonId)
  msg = msg + fmt.Sprintf("\tSubjectUserSid=%v", subjectUserSid)
  msg = msg + fmt.Sprintf("\tSubjectUserName=%v", subjectUserName)
  msg = msg + fmt.Sprintf("\tSubjectDomainName=%v", subjectDomainName)
  msg = msg + fmt.Sprintf("\tSubjectLogonId=%v", subjectLogonId)
  msg = msg + fmt.Sprintf("\tLogonType=%v", logonType)
  msg = msg + fmt.Sprintf("\tLogonProcessName=%v", logonProcessName)
  msg = msg + fmt.Sprintf("\tAuthenticationPackageName=%v", authenticationPackageName)
  msg = msg + fmt.Sprintf("\tWorkstationName=%v", workstationName)
  msg = msg + fmt.Sprintf("\tLogonGuid=%v", logonGuid)
  msg = msg + fmt.Sprintf("\tProcessName=%v", processName)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)

  return msg
} // func Event4624

// ----------------------------------------------------------------------------
// Event 4625  CL  An account failed to log on.
//
func Event4625(event *Event) string {
  targetUserSid := event.FindEventData("TargetUserSid")
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  subjectUserSid := event.FindEventData("SubjectUserSid")
  subjectUserName := event.FindEventData("SubjectUserName")
  subjectDomainName := event.FindEventData("SubjectDomainName")
  subjectLogonId := event.FindEventData("SubjectLogonId")
  failureReason := event.FindEventData("FailureReason")
  status := event.FindEventData("Status")
  subStatus := event.FindEventData("SubStatus")
  logonType := event.FindEventData("LogonType")
  logonProcessName := event.FindEventData("LogonProcessName")
  authenticationPackageName := event.FindEventData("AuthenticationPackageName")
  workstationName := event.FindEventData("WorkstationName")
  processName := event.FindEventData("ProcessName")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")

  logonType = ConvertLogonType(logonType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserSid=%v", targetUserSid)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tSubjectUserSid=%v", subjectUserSid)
  msg = msg + fmt.Sprintf("\tSubjectUserName=%v", subjectUserName)
  msg = msg + fmt.Sprintf("\tSubjectDomainName=%v", subjectDomainName)
  msg = msg + fmt.Sprintf("\tSubjectLogonId=%v", subjectLogonId)
  msg = msg + fmt.Sprintf("\tFailureReason=%v", failureReason)
  msg = msg + fmt.Sprintf("\tStatus=%v", status)
  msg = msg + fmt.Sprintf("\tSubStatus=%v", subStatus)
  msg = msg + fmt.Sprintf("\tLogonType=%v", logonType)
  msg = msg + fmt.Sprintf("\tLogonProcessName=%v", logonProcessName)
  msg = msg + fmt.Sprintf("\tAuthenticationPackageName=%v", authenticationPackageName)
  msg = msg + fmt.Sprintf("\tWorkstationName=%v", workstationName)
  msg = msg + fmt.Sprintf("\tProcessName=%v", processName)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)

  return msg
} // func Event4625

// ----------------------------------------------------------------------------
// Event 4634  CL  An account was logged off.
//
func Event4634(event *Event) string {
  targetUserSid := event.FindEventData("TargetUserSid")
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetLogonId := event.FindEventData("TargetLogonId")
  logonType := event.FindEventData("LogonType")

  logonType = ConvertLogonType(logonType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserSid=%v", targetUserSid)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetLogonId=%v", targetLogonId)
  msg = msg + fmt.Sprintf("\tLogonType=%v", logonType)

  return msg
} // func Event4634

// ----------------------------------------------------------------------------
// Event 4647  CL  User initiated logoff.
//
func Event4647(event *Event) string {
  targetUserSid := event.FindEventData("TargetUserSid")
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetLogonId := event.FindEventData("TargetLogonId")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserSid=%v", targetUserSid)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetLogonId=%v", targetLogonId)

  return msg
} // func Event4647

// ----------------------------------------------------------------------------
// Event 4648  CL  A logon was attempted using explicit credentials.
//
func Event4648(event *Event) string {
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetServerName := event.FindEventData("TargetServerName")
  targetInfo := event.FindEventData("TargetInfo")
  subjectUserSid := event.FindEventData("SubjectUserSid")
  subjectUserName := event.FindEventData("SubjectUserName")
  subjectDomainName := event.FindEventData("SubjectDomainName")
  subjectLogonId := event.FindEventData("SubjectLogonId")
  logonGuid := event.FindEventData("LogonGuid")
  processName := event.FindEventData("ProcessName")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetServerName=%v", targetServerName)
  msg = msg + fmt.Sprintf("\tTargetInfo=%v", targetInfo)
  msg = msg + fmt.Sprintf("\tSubjectUserSid=%v", subjectUserSid)
  msg = msg + fmt.Sprintf("\tSubjectUserName=%v", subjectUserName)
  msg = msg + fmt.Sprintf("\tSubjectDomainName=%v", subjectDomainName)
  msg = msg + fmt.Sprintf("\tSubjectLogonId=%v", subjectLogonId)
  msg = msg + fmt.Sprintf("\tLogonGuid=%v", logonGuid)
  msg = msg + fmt.Sprintf("\tProcessName=%v", processName)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)

  return msg
} // func Event4648

// ----------------------------------------------------------------------------
// Event 4672  CL  Special privileges assigned to new logon.
//
func Event4672(event *Event) string {
  subjectUserSid := event.FindEventData("SubjectUserSid")
  subjectUserName := event.FindEventData("SubjectUserName")
  subjectDomainName := event.FindEventData("SubjectDomainName")
  subjectLogonId := event.FindEventData("SubjectLogonId")
  privilegeList := event.FindEventData("PrivilegeList")
  privilegeList = strings.ReplaceAll(privilegeList, "\n", ",")
  privilegeList = strings.ReplaceAll(privilegeList, " ", "")
  privilegeList = strings.ReplaceAll(privilegeList, "\t", "")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tSubjectUserSid=%v", subjectUserSid)
  msg = msg + fmt.Sprintf("\tSubjectUserName=%v", subjectUserName)
  msg = msg + fmt.Sprintf("\tSubjectDomainName=%v", subjectDomainName)
  msg = msg + fmt.Sprintf("\tSubjectLogonId=%v", subjectLogonId)
  msg = msg + fmt.Sprintf("\tPrivilegeList=%v", privilegeList)

  return msg
} // func Event4672

// ----------------------------------------------------------------------------
// Event 4768  DC  A Kerberos authentication ticket (TGT) was requested.
//
func Event4768(event *Event) string {
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetSid := event.FindEventData("TargetSid")
  serviceName := event.FindEventData("ServiceName")
  serviceSid := event.FindEventData("ServiceSid")
  ticketOptions := event.FindEventData("TicketOptions")
  status := event.FindEventData("Status")
  ticketEncryptionType := event.FindEventData("TicketEncryptionType")
  preAuthType := event.FindEventData("PreAuthType")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")
  certIssuerName := event.FindEventData("CertIssuerName")
  certSerialNumber := event.FindEventData("CertSerialNumber")

  status = ConvertKerberosStatus(status)
  ticketEncryptionType = ConvertTicketEncryptionType(ticketEncryptionType)
  preAuthType = ConvertPreAuthType(preAuthType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetSid=%v", targetSid)
  msg = msg + fmt.Sprintf("\tServiceName=%v", serviceName)
  msg = msg + fmt.Sprintf("\tServiceSid=%v", serviceSid)
  msg = msg + fmt.Sprintf("\tTicketOptions=%v", ticketOptions)
  msg = msg + fmt.Sprintf("\tStatus=%v", status)
  msg = msg + fmt.Sprintf("\tTicketEncryptionType=%v", ticketEncryptionType)
  msg = msg + fmt.Sprintf("\tPreAuthType=%v", preAuthType)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)
  msg = msg + fmt.Sprintf("\tCertIssuerName=%v", certIssuerName)
  msg = msg + fmt.Sprintf("\tCertSerialNumber=%v", certSerialNumber)

  return msg
} // func Event4768

// ----------------------------------------------------------------------------
// Event 4769  DC  A Kerberos service ticket was requested.
//
func Event4769(event *Event) string {
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  serviceName := event.FindEventData("ServiceName")
  serviceSid := event.FindEventData("ServiceSid")
  ticketOptions := event.FindEventData("TicketOptions")
  ticketEncryptionType := event.FindEventData("TicketEncryptionType")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")
  status := event.FindEventData("Status")
  logonGuid := event.FindEventData("LogonGuid")
  transmittedServices := event.FindEventData("TransmittedServices")

  status = ConvertKerberosStatus(status)
  ticketEncryptionType = ConvertTicketEncryptionType(ticketEncryptionType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tServiceName=%v", serviceName)
  msg = msg + fmt.Sprintf("\tServiceSid=%v", serviceSid)
  msg = msg + fmt.Sprintf("\tTicketOptions=%v", ticketOptions)
  msg = msg + fmt.Sprintf("\tTicketEncryptionType=%v", ticketEncryptionType)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)
  msg = msg + fmt.Sprintf("\tStatus=%v", status)
  msg = msg + fmt.Sprintf("\tLogonGuid=%v", logonGuid)
  msg = msg + fmt.Sprintf("\tTransmittedServices=%v", transmittedServices)

  return msg
} // func Event4769

// ----------------------------------------------------------------------------
// Event 4770  DC  A Kerberos service ticket was renewed.
//
func Event4770(event *Event) string {
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  serviceName := event.FindEventData("ServiceName")
  serviceSid := event.FindEventData("ServiceSid")
  ticketOptions := event.FindEventData("TicketOptions")
  ticketEncryptionType := event.FindEventData("TicketEncryptionType")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")

  ticketEncryptionType = ConvertTicketEncryptionType(ticketEncryptionType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tServiceName=%v", serviceName)
  msg = msg + fmt.Sprintf("\tServiceSid=%v", serviceSid)
  msg = msg + fmt.Sprintf("\tTicketOptions=%v", ticketOptions)
  msg = msg + fmt.Sprintf("\tTicketEncryptionType=%v", ticketEncryptionType)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)

  return msg
} // func Event4770

// ----------------------------------------------------------------------------
// Event 4771  DC  Kerberos pre-authentication failed.
//
func Event4771(event *Event) string {
  targetUserName := event.FindEventData("TargetUserName")
  targetSid := event.FindEventData("TargetSid")
  serviceName := event.FindEventData("ServiceName")
  ticketOptions := event.FindEventData("TicketOptions")
  status := event.FindEventData("Status")
  preAuthType := event.FindEventData("PreAuthType")
  ipAddress := event.FindEventData("IpAddress")
  ipPort := event.FindEventData("IpPort")
  certIssuerName := event.FindEventData("CertIssuerName")
  certSerialNumber := event.FindEventData("CertSerialNumber")

  status = ConvertKerberosStatus(status)
  preAuthType = ConvertPreAuthType(preAuthType)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetSid=%v", targetSid)
  msg = msg + fmt.Sprintf("\tServiceName=%v", serviceName)
  msg = msg + fmt.Sprintf("\tTicketOptions=%v", ticketOptions)
  msg = msg + fmt.Sprintf("\tStatus=%v", status)
  msg = msg + fmt.Sprintf("\tPreAuthType=%v", preAuthType)
  msg = msg + fmt.Sprintf("\tIpAddress=%v", ipAddress)
  msg = msg + fmt.Sprintf("\tIpPort=%v", ipPort)
  msg = msg + fmt.Sprintf("\tCertIssuerName=%v", certIssuerName)
  msg = msg + fmt.Sprintf("\tCertSerialNumber=%v", certSerialNumber)

  return msg
} // func Event4771

// ----------------------------------------------------------------------------
// Event 4776  DC  The computer attempted to validate the credentials for an account.
//
func Event4776(event *Event) string {
  packageName := event.FindEventData("PackageName")
  targetUserName := event.FindEventData("TargetUserName")
  workstation := event.FindEventData("Workstation")
  status := event.FindEventData("Status")

  status = ConvertMicrosoftAuthStatus(status)

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tPackageName=%v", packageName)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tWorkstation=%v", workstation)
  msg = msg + fmt.Sprintf("\tStatus=%v", status)

  return msg
} // func Event4776

// ----------------------------------------------------------------------------
// Event 4778  CL A session was reconnected to a Window Station.
//
func Event4778(event *Event) string {
  accountName := event.FindEventData("AccountName")
  accountDomain := event.FindEventData("AccountDomain")
  logonID := event.FindEventData("LogonID")
  sessionName := event.FindEventData("SessionName")
  clientName := event.FindEventData("ClientName")
  clientAddress := event.FindEventData("ClientAddress")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tAccountName=%v", accountName)
  msg = msg + fmt.Sprintf("\tAccountDomain=%v", accountDomain)
  msg = msg + fmt.Sprintf("\tLogonID=%v", logonID)
  msg = msg + fmt.Sprintf("\tSessionName=%v", sessionName)
  msg = msg + fmt.Sprintf("\tClientName=%v", clientName)
  msg = msg + fmt.Sprintf("\tClientAddress=%v", clientAddress)

  return msg
} // func Event4778

// ----------------------------------------------------------------------------
// Event 4779  CL A session was disconnected from a Window Station.
//
func Event4779(event *Event) string {
  accountName := event.FindEventData("AccountName")
  accountDomain := event.FindEventData("AccountDomain")
  logonID := event.FindEventData("LogonID")
  sessionName := event.FindEventData("SessionName")
  clientName := event.FindEventData("ClientName")
  clientAddress := event.FindEventData("ClientAddress")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tAccountName=%v", accountName)
  msg = msg + fmt.Sprintf("\tAccountDomain=%v", accountDomain)
  msg = msg + fmt.Sprintf("\tLogonID=%v", logonID)
  msg = msg + fmt.Sprintf("\tSessionName=%v", sessionName)
  msg = msg + fmt.Sprintf("\tClientName=%v", clientName)
  msg = msg + fmt.Sprintf("\tClientAddress=%v", clientAddress)

  return msg
} // func Event4779

// ----------------------------------------------------------------------------
// Event 4800  CL The workstation was locked.
//
func Event4800(event *Event) string {
  targetUserSid := event.FindEventData("TargetUserSid")
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetLogonId := event.FindEventData("TargetLogonId")
  sessionId := event.FindEventData("SessionId")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserSid=%v", targetUserSid)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetLogonId=%v", targetLogonId)
  msg = msg + fmt.Sprintf("\tSessionId=%v", sessionId)

  return msg
} // func Event4800

// ----------------------------------------------------------------------------
// Event 4801  CL The workstation was unlocked.
//
func Event4801(event *Event) string {
  targetUserSid := event.FindEventData("TargetUserSid")
  targetUserName := event.FindEventData("TargetUserName")
  targetDomainName := event.FindEventData("TargetDomainName")
  targetLogonId := event.FindEventData("TargetLogonId")
  sessionId := event.FindEventData("SessionId")

  msg := fmt.Sprintf("Event=%v", event.System.EventID)
  msg = msg + fmt.Sprintf("\tTargetUserSid=%v", targetUserSid)
  msg = msg + fmt.Sprintf("\tTargetUserName=%v", targetUserName)
  msg = msg + fmt.Sprintf("\tTargetDomainName=%v", targetDomainName)
  msg = msg + fmt.Sprintf("\tTargetLogonId=%v", targetLogonId)
  msg = msg + fmt.Sprintf("\tSessionId=%v", sessionId)

  return msg
} // func Event4801
