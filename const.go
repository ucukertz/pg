package pg

const (
	Head1 uint8 = 0x55
	Head2 uint8 = 0xAA
	PktMinLen uint8 = 7
	DVPktMinLen uint8 = 5
	DlenLen uint8 = 2
	TsyncDlen uint8 = 8
	SchHeadLen uint8 = 4
)

type CmdID = uint8 // Command ID
const (
	CmdHandshake CmdID = iota // Handshake
	CmdDeviceInfo // Device info
	CmdNetworkReset // Network reset
	CmdNetworkStatus // Network status
	CmdTimeSync // Time syncronization
	CmdDVSet // Set Data Value
	CmdDVReport // Report Data Value
	CmdDVFault // Report faulty Data Value
	CmdSchedule // Data Value scheduling
)

type Handshake = uint8 // Handshake data byte
const (
	Heartbeat Handshake = iota // This device is alive
	HeartbeatACK // Acknowledge the other device is alive
	TxFinish // All data needed was already transmitted
	TxProcessed // All data needed was already processed
)

type DeviceInfoRB = uint8 // Device info request byte
const (
	TopicPrefix DeviceInfoRB = iota
	DevicePrefix
	DeviceName
)

type DeviceInfoIdx = uint8
const (
	IdxDevInfoReqbyte DeviceInfoIdx = iota
	IdxDevInfoResp
)

type NetworkResetRB = uint8 // Network reset request byte
const (
	NetDefault NetworkResetRB = iota
	NetAP // Access Point
	NetSC // Smart Config
	NetQC // Quick
	NetFactory NetworkResetRB = 0xFF
)

type NetworkStatusData = uint8
const (
	NetNG NetworkStatusData = iota // Not configured
	NetRouterNG // Configured but not connected to router
	NetCloudNG // Connected to router but not connected to cloud
	NetCloudOK // Connected to cloud

	// Pairing
	PairingAP NetworkStatusData = 0xA1 // Access Point
	PairingSC // Smart Config
	PairingQC // Quick
)

type TimesyncRB = uint8 // Time synchronization request byte
const (
	TsyncUTC TimesyncRB = iota
	TsyncLocal
)

type TimeSyncIdx = uint8
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

type DVGroup uint8
const (
	DvgInfo DVGroup = iota
	DvgSensor
	DvgControl
)

type DVtype uint8
const (
	DVtypeRaw DVtype = iota
	DVtypeString
	DVtypeBool
	DVtypeEnum
	DVtypeUint
	DVtypeBmap1
	DVtypeBmap2
	DVtypeBmap4
)

type IdxBasePkt = uint8
const (
	IdxHead1 IdxBasePkt = iota
	IdxHead2
	IdxVer
	IdxCmd
	IdxDlen
	IdxData IdxBasePkt = IdxDlen + IdxBasePkt(DlenLen)
)

type IdxDVPkt = uint8
const (
	IdxDVPGroup IdxDVPkt = iota
	IdxDVPID
	IdxDVPtype
	IdxDVPdlen
	IdxDVPdata IdxDVPkt = IdxDVPdlen+IdxDVPkt(DlenLen)
)

type DvtypeLen = uint8 // Fixed data Length of some DV types
const (
	LenBool DvtypeLen = 1
	LenEnum DvtypeLen = 1
	LenUint DvtypeLen = 4
	LenBmap1 DvtypeLen = 1 
	LenBmap2 DvtypeLen = 2
	LenBmap4 DvtypeLen = 4
)

type DVfault = uint8 // Data value fault
const (
	DvfNone DVfault = iota
	DvfUnknown
	DVfBroken
	DvfNotAvailable
	DvfUnstable
	DvfMalfunction
	DvfAnomalous
	DvfMalformed
)

type IdxDvfault = uint8
const (
	IdxDvfGroup IdxDvfault = iota
	IdxDvfID
	IdxDvfStatus
)

type idxSchPkt = uint8
const (
	IdxSchpID idxSchPkt = iota
	IdxSchpWday
	IdxSchpHour
	IdxSchpMinute
	IdxSchpDvp
)