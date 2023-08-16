package pg

const (
	Head1       byte = 0x55
	Head2       byte = 0xAA
	PktMinLen   byte = 7
	DEPktMinLen byte = 5
	DlenLen     byte = 2
	TsyncDlen   byte = 8
	SchHeadLen  byte = 4
)

type CmdID = byte // Command ID
const (
	CmdHandshake     CmdID = iota // Handshake
	CmdUplinkInfo                 // Uplink info
	CmdNetworkReset               // Network reset
	CmdNetworkStatus              // Network status
	CmdTimeSync                   // Time synchronization
	CmdDESet                      // Set Data Entity
	CmdDEReport                   // Report Data Entity
	CmdDEFault                    // Report faulty Data Entity
	CmdSchedule                   // Data Entity scheduling
)

type Handshake = byte // Handshake data byte
const (
	Heartbeat    Handshake = iota // This device is alive
	HeartbeatACK                  // Acknowledge the other device is alive
	DeTxFinish                    // All Data Entity needed for uplink transmitted
	DeUplinked                    // All received Data Entity uplinked
)

type DeviceInfoRB = byte // Device info request byte
const (
	UplinkDest DeviceInfoRB = iota
	DeviceType
	DeviceName
	DeviceID
)

type DeviceInfoIdx = byte

const (
	IdxDevInfoReqbyte DeviceInfoIdx = iota
	IdxDevInfoResp
)

type NetworkResetRB = byte // Network reset request byte
const (
	NetDefault NetworkResetRB = iota
	NetAP                     // Access Point
	NetSC                     // Smart Config
	NetQC                     // Quick
)

type NetworkStatusData = byte

const (
	NetCfgNG    NetworkStatusData = iota // Not configured
	NetConnNG                            // Configured but connection can't be established
	NetUplinkNG                          // Connected but can't uplink
	NetUplinkOK                          // Uplink can be done

	// Configuring
	CfgAP NetworkStatusData = 0xA1 // Access Point
	CfgSC                          // Smart Config
	CfgQC                          // Quick
)

type TimesyncRB = byte // Time synchronization request byte
const (
	TsyncUTC TimesyncRB = iota
	TsyncLocal
)

type TimeSyncIdx = byte

const (
	IdxTsyncReqbyte TimeSyncIdx = iota
	IdxTsyncYear
	IdxTsyncMonth
	IdxTsyncDate
	IdxTsyncWeekday // 0 = Sunday - 6 = Saturday
	IdxTsyncHour
	IdxTsyncMinute
	IdxTsyncSecond
)

type DEGroup byte

const (
	DegInfo DEGroup = iota
	DegSensor
	DegControl
)

type DEtype byte

const (
	DEtypeRaw DEtype = iota
	DEtypeString
	DEtypeBool
	DEtypeEnum
	DEtypeUint
	DEtypeBmap1
	DEtypeBmap2
	DEtypeBmap4
)

type IdxBasePkt = byte

const (
	IdxHead1 IdxBasePkt = iota
	IdxHead2
	IdxVer
	IdxCmd
	IdxDlen
	IdxData IdxBasePkt = IdxDlen + IdxBasePkt(DlenLen)
)

type IdxDEPkt = byte

const (
	IdxDEPGroup IdxDEPkt = iota
	IdxDEPID
	IdxDEPtype
	IdxDEPdlen
	IdxDEPdata IdxDEPkt = IdxDEPdlen + IdxDEPkt(DlenLen)
)

type DetypeLen = byte // Fixed data Length of some DE types
const (
	LenBool  DetypeLen = 1
	LenEnum  DetypeLen = 1
	LenUint  DetypeLen = 4
	LenBmap1 DetypeLen = 1
	LenBmap2 DetypeLen = 2
	LenBmap4 DetypeLen = 4
)

type DEF = byte // Data Entity fault
const (
	DefNone DEF = iota
	DefUnknown
	DefBroken
	DefNotAvailable
	DefUnstable
	DefMalfunction
	DefAnomalous
	DefMalformed
)

type IdxDef = byte

const (
	IdxDefGroup IdxDef = iota
	IdxDefID
	IdxDefStatus
)

type idxSchPkt = byte

const (
	IdxSchpID idxSchPkt = iota
	IdxSchpWday
	IdxSchpHour
	IdxSchpMinute
	IdxSchpDep
)
