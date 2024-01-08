package pg

type Error struct {
	msg string
}

func (e *Error) Error() string {
	return e.msg
}

var (
	ErrChksum      = &Error{"PG chksum"}
	ErrCmdId       = &Error{"PG invalid CMD ID"}
	ErrTooShort    = &Error{"PG too short"}
	ErrLenMismatch = &Error{"PG data length mismatch"}
	ErrInvalidData = &Error{"PG invalid data"}
	ErrSchedule    = &Error{"PG schedule"}
)

const (
	Head1 byte = 0x55
	Head2 byte = 0xAA
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
	CmdSwUpdate                   // Software update
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

type SwupScmd = byte

const (
	SwupScmdInitiate SwupScmd = iota
	SwupScmdSrep
	SwupScmdChunksz
	SwupScmdStatus
	SwupScmdChunkReq
	SwupScmdChunk
)

type SwupSrep = byte

const (
	SrepAccept SwupSrep = iota
	SrepReject
	SrepNoInfo
	SrepBusy
)

type SwupErr = byte

const (
	SwupOk SwupErr = iota
	SwupErrUnknown
	SwupErrConn
	SwupErrOom
)

type SwupStatus struct {
	Finish  bool
	Success bool
	Err     SwupErr
}

type SwupChunk struct {
	Size uint16
	Idx  uint32
	Data []byte
}

type Swup struct {
	Scmd   SwupScmd
	Srep   SwupSrep
	Status SwupStatus
	Chunk  SwupChunk
}

/* LENGTHS */

const (
	LenPktMin   byte = 7
	LenDePktMin byte = 5
	LenDlen     byte = 2
	LenTsync    byte = 8
	LenSchHead  byte = 4

	LenDeBool  uint16 = 1
	LenDeEnum  uint16 = 1
	LenDeUint  uint16 = 4
	LenDeBmap1 uint16 = 1
	LenDeBmap2 uint16 = 2
	LenDeBmap4 uint16 = 4
)

const (
	LenSwupDataInitiate uint16 = iota
	LenSwupDataSrep
	LenSwupDataChunksz
	LenSwupDataStatus
	LenSwupDataChunkReq
	LenSwupDataChunk
)

/* INDEXES */

const (
	IdxDevInfoReqbyte byte = iota
	IdxDevInfoResp
)

const (
	IdxTsyncReqbyte byte = iota
	IdxTsyncYear
	IdxTsyncMonth
	IdxTsyncDate
	IdxTsyncWeekday // 0 = Sunday - 6 = Saturday
	IdxTsyncHour
	IdxTsyncMinute
	IdxTsyncSecond
)

const (
	IdxHead1 byte = iota
	IdxHead2
	IdxVer
	IdxCmd
	IdxDlen
	IdxData byte = IdxDlen + LenDlen
)

const (
	IdxDEPGroup byte = iota
	IdxDEPID
	IdxDEPtype
	IdxDEPdlen
	IdxDEPdata byte = IdxDEPdlen + LenDlen
)

const (
	IdxDefGroup byte = iota
	IdxDefID
	IdxDefStatus
)

const (
	IdxSchpID byte = iota
	IdxSchpWday
	IdxSchpHour
	IdxSchpMinute
	IdxSchpDep
)

const (
	IdxSwupStatFinished byte = iota
	IdxSwupStatSuccess
	IdxSwupStatError
)

const (
	IdxSwupChunkidx  byte = iota
	IdxSwupChunkData byte = 4
)
