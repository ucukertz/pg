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

type DeviceInfoRB = byte // Device info request byte
const (
	UplinkDest DeviceInfoRB = iota
	DeviceType
	DeviceName
	DeviceID
)

type NetRstRB = byte // Network reset request byte
const (
	NetDefault NetRstRB = iota
	NetAP               // Access Point
	NetSC               // Smart Config
	NetQC               // Quick
)

type NetstatData = byte // Network status data
const (
	NetstatNoCfg    NetstatData = iota // Not configured
	NetstatNoConn                      // Configured but connection can't be established
	NetstatNoUplink                    // Connected but can't uplink
	NetstatOk                          // Uplink can be done
)

// Net configuring
const (
	NetstatCfgAP NetstatData = iota + 0xA1 // Access Point
	NetstatCfgSC                           // Smart Config
	NetstatCfgQC                           // Quick
)

type TimesyncRB = byte // Time synchronization request byte
const (
	TsyncUTC TimesyncRB = iota
	TsyncLocal
)

type DEGroup byte // Data Entity group
const (
	DegInfo DEGroup = iota
	DegSensor
	DegControl
)

type DEtype byte // Data Entity types
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

type SwupScmd = byte // Software update subcommands
const (
	SwupScmdInitiate SwupScmd = iota
	SwupScmdSrep
	SwupScmdChunksz
	SwupScmdStatus
	SwupScmdChunkReq
	SwupScmdChunk
)

type SwupSrep = byte // Software update simple reply byte
const (
	SrepAccept SwupSrep = iota
	SrepReject
	SrepNoInfo
	SrepBusy
)

type SwupErr = byte // Software update error
const (
	SwupOk SwupErr = iota
	SwupErrUnknown
	SwupErrConn
	SwupErrOom
)

// Software update status
type SwupStatus struct {
	Finish  bool
	Success bool
	Err     SwupErr
}

// Software update chunk
type SwupChunk struct {
	Size uint16
	Idx  uint32
	Data []byte
}

// Software update packet info
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
	IdxSwupSrep      byte = 0
	IdxSwupChunkidx  byte = 0
	IdxSwupChunkData byte = 4
)
