// Implements pg protocol
package pg

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Unbuilt pg packet
type BuildPkt struct {
	Ver       byte
	CommandID CmdID
	DataLen   uint16
	Data      []byte
}

// Base pg packet
type BasePkt struct {
	Ver       byte
	CommandID CmdID
	DataLen   uint16
	Data      []byte
	Buf       []byte
	Chksum    byte
}

// DE packet
type DePkt struct {
	Group   DEGroup
	Id      byte
	Dtype   DEtype
	Dlen    uint16
	DataRaw []byte
	Data    uint32
	Buf     []byte
}

// Schedule packet
type SchPkt struct {
	Id       byte
	Weekdays byte
	Hour     byte
	Minute   byte
	Dep      DePkt
}

var PgVer byte = 0 // Active pg version

// Set active pg version
func SetVer(ver byte) {
	PgVer = ver
}

// Sum of all bytes in slice
func Chksum(buf []byte) byte {
	var chksum byte = 0
	for _, b := range buf {
		chksum += b
	}
	return chksum
}

// Verify checksum of buf is the same as chksum
func ChksumVerify(buf []byte, chksum byte) error {
	expected := Chksum(buf)
	if chksum != expected {
		return fmt.Errorf("%w expected 0x%x but got 0x%x", ErrChksum, expected, chksum)
	}
	return nil
}

// Create unbuilt packet with cid as Command ID
func Create(cid CmdID) BuildPkt {
	return BuildPkt{Ver: PgVer, CommandID: cid, DataLen: 0, Data: make([]byte, 0, 32)}
}

// Append one byte to unbuilt packet
func (pkt *BuildPkt) AppendOne(data byte) {
	pkt.DataLen += 1
	pkt.Data = append(pkt.Data, data)
}

// Append multiple bytes to unbuilt packet
func (pkt *BuildPkt) Append(data []byte) {
	pkt.DataLen += uint16(len(data))
	pkt.Data = append(pkt.Data, data...)
}

// Convert u16 value to its big endlian slice representation
func U16ToBslice(v uint16) []byte {
	var slice [2]byte
	binary.BigEndian.PutUint16(slice[:], v)
	return slice[:]
}

// Convert uint32 value to its big endlian slice representation
func U32ToBslice(v uint32) []byte {
	var slice [4]byte
	binary.BigEndian.PutUint32(slice[:], v)
	return slice[:]
}

// Build DE packet from parameters then append it to unbuilt packet
func (pkt *BuildPkt) AppendDEPkt(g DEGroup, id byte, t DEtype, dlen uint16, data []byte) {
	pkt.Append([]byte{byte(g), id, byte(t)})
	dlenBig := U16ToBslice(dlen)
	pkt.Append(dlenBig)
	pkt.Append(data[:dlen])
}

// Build DE packet with fixed data length from parameters then append it to unbuilt packet
func (pkt *BuildPkt) AppendDEPktFixed(g DEGroup, id byte, t DEtype, dlen uint16, data uint32) {
	dlen = EnforceDElen(t, dlen)
	pkt.Append([]byte{byte(g), id, byte(t)})
	dlenBig := U16ToBslice(dlen)
	pkt.Append(dlenBig)
	if dlen == 1 {
		pkt.AppendOne(byte(data))
	} else if dlen == 2 {
		dataBig := U16ToBslice(uint16(data))
		pkt.Append(dataBig)
	} else if dlen == 4 {
		dataBig := U32ToBslice(uint32(data))
		pkt.Append(dataBig)
	}
}

// Transform unbuilt packet into base packet
func (p BuildPkt) Build() BasePkt {
	Pkt := BasePkt{Ver: p.Ver, CommandID: p.CommandID, DataLen: p.DataLen, Data: p.Data}
	buf := make([]byte, 0, int(LenPktMin)+len(p.Data))
	buf = append(buf, Head1, Head2, Pkt.Ver, Pkt.CommandID)
	buf = binary.BigEndian.AppendUint16(buf, Pkt.DataLen)
	buf = append(buf, Pkt.Data...)
	buf = append(buf, Chksum(buf))
	Pkt.Buf = buf
	return Pkt
}

func (p BasePkt) String() string {
	return fmt.Sprintf("ver: %d cmd: %d dlen: %d, data:[0x%x] cs: 0x%x",
		p.Ver, p.CommandID, p.DataLen, p.Data, p.Chksum)
}

func (g DEGroup) String() string {
	switch g {
	case DegInfo:
		return "Info"
	case DegSensor:
		return "Sensor"
	case DegControl:
		return "Control"
	default:
		return "Invalid"
	}
}

func (t DEtype) String() string {
	switch t {
	case DEtypeRaw:
		return "Raw"
	case DEtypeString:
		return "String"
	case DEtypeBool:
		return "Bool"
	case DEtypeEnum:
		return "Enum"
	case DEtypeUint:
		return "Uint"
	case DEtypeBmap1:
		return "Bmap1"
	case DEtypeBmap2:
		return "Bmap2"
	case DEtypeBmap4:
		return "Bmap4"
	default:
		return "Invalid"
	}
}

func (p DePkt) String() string {
	switch p.Dtype {
	case DEtypeRaw:
		return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x]",
			p.Group, p.Id, p.Dtype, p.Dlen, p.DataRaw)
	case DEtypeString:
		return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x] data: %s",
			p.Group, p.Id, p.Dtype, p.Dlen, p.DataRaw, p.DataRaw)
	default:
		return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x] data: %d",
			p.Group, p.Id, p.Dtype, p.Dlen, p.DataRaw, p.Data)
	}
}

func (p SchPkt) String() string {
	return fmt.Sprintf("id: %d wdays: %08b hour: %d minute: %d dep:[%s]", p.Id, p.Weekdays, p.Hour, p.Minute, p.Dep)
}

// Make handshake packet
func MkHandshake(msg []byte) []byte {
	p := Create(CmdHandshake)
	p.Append(msg)
	return p.Build().Buf
}

// Make all uplink info request packet
func MkUinfoReqAll() []byte {
	p := Create(CmdUplinkInfo)
	return p.Build().Buf
}

// Make uplink info request packet
func MkUinfoReq(rb DeviceInfoRB) []byte {
	p := Create(CmdUplinkInfo)
	p.AppendOne(rb)
	return p.Build().Buf
}

// Make uplink info response packet
func MkUinfoResp(rb DeviceInfoRB, resp string) []byte {
	p := Create(CmdUplinkInfo)
	p.AppendOne(rb)
	p.Append([]byte(resp))
	return p.Build().Buf
}

// Make network reset request packet
func MkNetResetReq(rb NetRstRB) []byte {
	p := Create(CmdNetworkReset)
	p.AppendOne(rb)
	return p.Build().Buf
}

// Make network reset acknowledgement packet
func MkNetResetACK() []byte {
	p := Create(CmdNetworkReset)
	return p.Build().Buf
}

// Make network status report acknowledgement packet
func MkNetStatusReportACK() []byte {
	p := Create(CmdNetworkStatus)
	return p.Build().Buf
}

// Make network status report packet
func MkNetStatusReport(r NetstatData) []byte {
	p := Create(CmdNetworkStatus)
	p.AppendOne(r)
	return p.Build().Buf
}

// Make time synchronization not ready packet
func MkTsyncNotReady() []byte {
	p := Create(CmdTimeSync)
	return p.Build().Buf
}

// Make time synchronization request packet
func MkTsyncReq(rb TimesyncRB) []byte {
	p := Create(CmdTimeSync)
	p.AppendOne(rb)
	return p.Build().Buf
}

// Make time synchronization response packet
func MkTsyncResp(rb TimesyncRB, tm time.Time) []byte {
	p := Create(CmdTimeSync)
	p.AppendOne(rb)
	p.AppendOne(byte(tm.Year() - 100))
	p.AppendOne(byte(tm.Month()))
	p.AppendOne(byte(tm.Day()))
	p.AppendOne(byte(tm.Weekday()))
	p.AppendOne(byte(tm.Hour()))
	p.AppendOne(byte(tm.Minute()))
	p.AppendOne(byte(tm.Second()))
	return p.Build().Buf
}

// Make DE reset request packet
func MkDeResetAllReq() []byte {
	p := Create(CmdDESet)
	return p.Build().Buf
}

// Enforce DE data length for DE data types with fixed length
func EnforceDElen(t DEtype, dlen uint16) uint16 {
	switch t {
	case DEtypeBool:
		return LenDeBool
	case DEtypeEnum:
		return LenDeEnum
	case DEtypeUint:
		return LenDeUint
	case DEtypeBmap1:
		return LenDeBmap1
	case DEtypeBmap2:
		return LenDeBmap2
	case DEtypeBmap4:
		return LenDeBmap4
	default:
		return dlen
	}
}

// Make DE set packet
func MkDES(g DEGroup, id byte, t DEtype, dlen uint16, data []byte) []byte {
	p := Create(CmdDESet)
	dlen = EnforceDElen(t, dlen)
	p.AppendDEPkt(g, id, t, dlen, data)
	return p.Build().Buf
}

// Make DE set packet: Raw
func MkDeSetRaw(g DEGroup, id byte, data []byte) []byte {
	return MkDES(g, id, DEtypeRaw, uint16(len(data)), data)
}

// Make DE set packet: String
func MkDeSetStr(g DEGroup, id byte, data string) []byte {
	return MkDES(g, id, DEtypeString, uint16(len(data)), []byte(data))
}

// Make DE set packet: Boolean
func MkDeSetBool(g DEGroup, id byte, data bool) []byte {
	var d byte = 0
	if data {
		d = 1
	}
	return MkDES(g, id, DEtypeBool, LenDeBool, []byte{d})
}

// Make DE set packet: Enumeration
func MkDeSetEnum(g DEGroup, id byte, data byte) []byte {
	return MkDES(g, id, DEtypeEnum, LenDeEnum, []byte{data})
}

// Make DE set packet: Uint/value
func MkDeSetUint(g DEGroup, id byte, data uint32) []byte {
	dataBig := U32ToBslice(data)
	return MkDES(g, id, DEtypeUint, LenDeUint, dataBig)
}

// Make DE set packet: 1-byte bitmap
func MkDeSetBmap1(g DEGroup, id byte, data byte) []byte {
	return MkDES(g, id, DEtypeBmap1, LenDeBmap1, []byte{data})
}

// Make DE set packet: 2-byte bitmap
func MkDeSetBmap2(g DEGroup, id byte, data uint16) []byte {
	dataBig := U16ToBslice(data)
	return MkDES(g, id, DEtypeBmap2, LenDeBmap2, dataBig)
}

// Make DE set packet: 4-byte bitmap
func MkDeSetBmap4(g DEGroup, id byte, data uint32) []byte {
	dataBig := U32ToBslice(data)
	return MkDES(g, id, DEtypeBmap4, LenDeBmap4, dataBig)
}

// Make DE report packet
func MkDER(g DEGroup, id byte, t DEtype, dlen uint16, data []byte) []byte {
	p := Create(CmdDEReport)
	dlen = EnforceDElen(t, dlen)
	p.AppendDEPkt(g, id, t, dlen, data)
	return p.Build().Buf
}

// Make DE report packet: Raw
func MkDeRepRaw(g DEGroup, id byte, data []byte) []byte {
	return MkDER(g, id, DEtypeRaw, uint16(len(data)), data)
}

// Make DE report packet: String
func MkDeRepStr(g DEGroup, id byte, data string) []byte {
	return MkDER(g, id, DEtypeString, uint16(len(data)), []byte(data))
}

// Make DE report packet: Boolean
func MkDeRepBool(g DEGroup, id byte, data bool) []byte {
	var d byte = 0
	if data {
		d = 1
	}
	return MkDER(g, id, DEtypeBool, LenDeBool, []byte{d})
}

// Make DE report packet: Enumeration
func MkDeRepEnum(g DEGroup, id byte, data byte) []byte {
	return MkDER(g, id, DEtypeEnum, LenDeEnum, []byte{data})
}

// Make DE report packet: Uint/value
func MkDeRepUint(g DEGroup, id byte, data uint32) []byte {
	dataBig := U32ToBslice(data)
	return MkDER(g, id, DEtypeUint, LenDeUint, dataBig)
}

// Make DE report packet: 1-Byte bitmap
func MkDeRepBmap1(g DEGroup, id byte, data byte) []byte {
	return MkDER(g, id, DEtypeBmap1, LenDeBmap1, []byte{data})
}

// Make DE report packet: 2-Byte bitmap
func MkDeRepBmap2(g DEGroup, id byte, data uint16) []byte {
	dataBig := U16ToBslice(data)
	return MkDER(g, id, DEtypeBmap2, LenDeBmap2, dataBig)
}

// Make DE report packet: 4-Byte bitmap
func MkDeRepBmap4(g DEGroup, id byte, data uint32) []byte {
	dataBig := U32ToBslice(data)
	return MkDER(g, id, DEtypeBmap4, LenDeBmap4, dataBig)
}

// Make DE fault report request packet
func MkDeFaultAllReq() []byte {
	p := Create(CmdDEFault)
	return p.Build().Buf
}

// Make DE fault report packet: No fault on all DE
func MkDeFaultNoneAll() []byte {
	p := Create(CmdDEFault)
	p.AppendOne(0)
	return p.Build().Buf
}

// Make DE fault acknowledgement packet
func MkDeFaultAck(g DEGroup, id byte) []byte {
	p := Create(CmdDEFault)
	p.AppendOne(byte(g))
	p.AppendOne(id)
	return p.Build().Buf
}

// Make DE fault report packet
func MkDeFaultRep(g DEGroup, id byte, f DEF) []byte {
	p := Create(CmdDEFault)
	p.AppendOne(byte(g))
	p.AppendOne(id)
	p.AppendOne(f)
	return p.Build().Buf
}

// Make schedule clear request packet
func MkSchEraseAllReq() []byte {
	p := Create(CmdSchedule)
	return p.Build().Buf
}

// Make schedule execution report packet
func MkSchExecReport(schId byte) []byte {
	p := Create(CmdSchedule)
	p.AppendOne(schId)
	return p.Build().Buf
}

// Make schedule set packet
func MkSchSet(schList []SchPkt) []byte {
	p := Create(CmdSchedule)
	p.AppendOne(byte(len(schList)))
	for _, sch := range schList {
		p.AppendOne(sch.Id)
		p.AppendOne(sch.Weekdays)
		p.AppendOne(sch.Hour)
		p.AppendOne(sch.Minute)
		dep := sch.Dep
		if sch.Dep.Dtype != DEtypeRaw && sch.Dep.Dtype != DEtypeString {
			p.AppendDEPktFixed(dep.Group, dep.Id, dep.Dtype, dep.Dlen, dep.Data)
		} else {
			p.AppendDEPkt(dep.Group, dep.Id, dep.Dtype, dep.Dlen, dep.DataRaw)
		}
	}
	return p.Build().Buf
}

// Make software update iniitiate packet
func MkSwupInitiate() []byte {
	p := Create(CmdSwUpdate)
	return p.Build().Buf
}

// Make sofware update simple reply packet
func MkSwupSrep(srep SwupSrep) []byte {
	p := Create(CmdSwUpdate)
	p.AppendOne(srep)
	return p.Build().Buf
}

// Make sofware update chunk size set packet
func MkSwupSetChunksz(chunksz uint16) []byte {
	p := Create(CmdSwUpdate)
	dataBig := U16ToBslice(chunksz)
	p.Append(dataBig)
	return p.Build().Buf
}

// Make sofware update status packet
func MkSwupStatus(finished bool, success bool, err SwupErr) []byte {
	p := Create(CmdSwUpdate)
	d := []byte{0, 0, 0}
	if finished {
		d[IdxSwupStatFinished] = 1
	}
	if success {
		d[IdxSwupStatSuccess] = 1
	}
	d[IdxSwupStatError] = err
	p.Append(d)
	return p.Build().Buf
}

// Make sofware update chunk request packet
func MkSwupChunkReq(chunkidx uint32) []byte {
	p := Create(CmdSwUpdate)
	dataBig := U32ToBslice(chunkidx)
	p.Append(dataBig)
	return p.Build().Buf
}

// Make sofware update chunk request packet
func MkSwupChunk(chunkidx uint32, chunk []byte) []byte {
	p := Create(CmdSwUpdate)
	dataBig := U32ToBslice(chunkidx)
	p.Append(dataBig)
	p.Append(chunk)
	return p.Build().Buf
}

// Parse buffer into base packet
func Parse(buf []byte) (BasePkt, error) {
	if len(buf) < int(LenPktMin) {
		return BasePkt{}, ErrTooShort
	}
	if buf[IdxHead1] != Head1 {
		return BasePkt{}, fmt.Errorf("%w: Header 1", ErrInvalidData)
	}
	if buf[IdxHead2] != Head2 {
		return BasePkt{}, fmt.Errorf("%w: Header 2", ErrInvalidData)
	}
	err := ChksumVerify(buf[:len(buf)-1], buf[len(buf)-1])
	if err != nil {
		return BasePkt{}, err
	}

	pkt := BasePkt{Ver: buf[IdxVer], CommandID: CmdID(buf[IdxCmd])}
	dlenSlice := buf[IdxDlen : IdxDlen+LenDlen]
	pkt.DataLen = binary.BigEndian.Uint16(dlenSlice)
	if len(buf) != int(LenPktMin)+int(pkt.DataLen) {
		return BasePkt{}, ErrLenMismatch
	}
	pkt.Data = buf[IdxData : uint16(IdxData)+pkt.DataLen]
	pkt.Buf = append(pkt.Buf, buf...)
	pkt.Chksum = buf[len(buf)-1]

	return pkt, nil
}

// Get numeric data from DE packet with fixed-length data type
func DepFixedData(p DePkt) uint32 {
	if p.Dlen == 1 {
		return uint32(p.DataRaw[0])
	} else if p.Dlen == 2 {
		data := binary.BigEndian.Uint16(p.DataRaw)
		return uint32(data)
	} else if p.Dlen == 4 {
		data := binary.BigEndian.Uint32(p.DataRaw)
		return data
	}
	return 0
}

// Parse buffer into DE packet
func ParseDEP(buf []byte) (DePkt, error) {
	if len(buf) < int(LenDePktMin) {
		return DePkt{}, ErrTooShort
	}
	dep := DePkt{}
	dep.Group = DEGroup(buf[IdxDEPGroup])
	dep.Id = buf[IdxDEPID]
	dep.Dtype = DEtype(buf[IdxDEPtype])
	dlenSlice := buf[IdxDEPdlen : IdxDEPdlen+LenDlen]
	dep.Dlen = binary.BigEndian.Uint16(dlenSlice)
	if len(buf) < int(LenDePktMin)+int(dep.Dlen) {
		return DePkt{}, ErrLenMismatch
	}
	dataSlice := buf[IdxDEPdata : IdxDEPdata+byte(dep.Dlen)]
	dep.DataRaw = append(dep.DataRaw, dataSlice...)
	dep.Buf = buf[:uint16(LenDePktMin)+dep.Dlen]

	if dep.Dtype != DEtypeRaw && dep.Dtype != DEtypeString {
		dep.Data = DepFixedData(dep)
	} else {
		dep.Data = 0
	}
	return dep, nil
}

// Get DE packet from base packet
// Can only be used when base packet data contains only and exclusively one DE packet
func (p BasePkt) GetDEP() (DePkt, error) {
	dep := DePkt{}
	if p.CommandID != CmdDESet && p.CommandID != CmdDEReport {
		return dep, ErrCmdId
	}
	return ParseDEP(p.Data)
}

// Get schedule list from base packet
func (p BasePkt) GetSchList() ([]SchPkt, error) {
	var err error = nil
	if p.CommandID != CmdSchedule {
		return []SchPkt{}, ErrCmdId
	}

	schNum := p.Data[0]
	schList := make([]SchPkt, schNum)
	pIdx := 1
	for i := range schList {
		sch := &schList[i]
		sch.Id = p.Data[pIdx+int(IdxSchpID)]
		sch.Weekdays = p.Data[pIdx+int(IdxSchpWday)]
		sch.Hour = p.Data[pIdx+int(IdxSchpHour)]
		sch.Minute = p.Data[pIdx+int(IdxSchpMinute)]
		sch.Dep, err = ParseDEP(p.Data[pIdx+int(IdxSchpDep):])
		if err != nil {
			return []SchPkt{}, fmt.Errorf("%w %w on schedule id %d", ErrSchedule, err, sch.Id)
		}
		pIdx += int(LenSchHead) + int(LenDePktMin) + int(sch.Dep.Dlen)
		if pIdx > int(p.DataLen)+1 {
			return []SchPkt{}, ErrLenMismatch
		}
	}

	return schList, nil
}

// Get Software update command info
func (p BasePkt) GetSwup() (Swup, error) {
	swup := Swup{}
	if p.CommandID != CmdSwUpdate {
		return swup, ErrCmdId
	}

	switch p.DataLen {
	case LenSwupDataInitiate:
		swup.Scmd = SwupScmdInitiate
	case LenSwupDataSrep:
		swup.Scmd = SwupScmdSrep
	case LenSwupDataChunksz:
		swup.Scmd = SwupScmdChunksz
	case LenSwupDataStatus:
		swup.Scmd = SwupScmdStatus
	case LenSwupDataChunkReq:
		swup.Scmd = SwupScmdChunkReq
	default:
		swup.Scmd = SwupScmdChunk
	}

	if swup.Scmd == SwupScmdChunkReq || swup.Scmd == SwupScmdChunk {
		swup.Chunk.Idx = binary.BigEndian.Uint32(p.Data)
		if swup.Scmd == SwupScmdChunk {
			swup.Chunk.Data = p.Data[IdxSwupChunkData:]
			swup.Chunk.Size = uint16(len(swup.Chunk.Data))
			return swup, nil
		}
	} else if swup.Scmd == SwupScmdChunksz {
		swup.Chunk.Size = binary.BigEndian.Uint16(p.Data)
	}

	if swup.Scmd == SwupScmdInitiate {
		return swup, nil
	} else if swup.Scmd == SwupScmdSrep {
		swup.Srep = p.Data[IdxSwupSrep]
	} else if swup.Scmd == SwupScmdStatus {
		swup.Status.Finish = p.Data[IdxSwupStatFinished] > 0
		swup.Status.Success = p.Data[IdxSwupStatSuccess] > 0
		swup.Status.Err = p.Data[IdxSwupStatError]
	}
	return swup, nil
}
