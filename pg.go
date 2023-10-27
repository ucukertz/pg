// Implements pg protocol
package pg

import (
	"bytes"
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
	if chksum == expected {
		return nil
	} else {
		return fmt.Errorf("CHKSUM got 0x%x but expected 0x%x", chksum, expected)
	}
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

func (pkt *BuildPkt) AppendDlen16(dlen uint16) {
	pkt.Data = binary.BigEndian.AppendUint16(pkt.Data, dlen)
	pkt.DataLen += 2
}

// Build DE packet from parameters then append it to unbuilt packet
func (pkt *BuildPkt) AppendDEPkt(g DEGroup, id byte, t DEtype, dlen uint16, data []byte) {
	pkt.Append([]byte{byte(g), id, byte(t)})
	pkt.AppendDlen16(dlen)
	pkt.Append(data[:dlen])
}

// Build DE packet with fixed data length from parameters then append it to unbuilt packet
func (pkt *BuildPkt) AppendDEPktFixed(g DEGroup, id byte, t DEtype, dlen uint16, data uint32) {
	dlen = EnforceDElen(t, dlen)
	pkt.Append([]byte{byte(g), id, byte(t)})
	pkt.AppendDlen16(dlen)
	if dlen == 1 {
		pkt.AppendOne(byte(data))
	} else if dlen == 2 {
		dataBig := []byte{}
		dataBig = binary.BigEndian.AppendUint16(dataBig, uint16(data))
		pkt.Append(dataBig)
	} else if dlen == 4 {
		dataBig := []byte{}
		dataBig = binary.BigEndian.AppendUint32(dataBig, data)
		pkt.Append(dataBig)
	}
}

// Transform unbuilt packet into base packet
func (p BuildPkt) Build() BasePkt {
	Pkt := BasePkt{Ver: p.Ver, CommandID: p.CommandID, DataLen: p.DataLen, Data: p.Data}
	buf := make([]byte, 0, int(PktMinLen)+len(p.Data))
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
func MkHandshake(hs Handshake) []byte {
	p := Create(CmdHandshake)
	p.AppendOne(hs)
	return p.Build().Buf
}

// Make connection end request handshake packet
func MkHandshakeEnd() []byte {
	p := Create(CmdHandshake)
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
func MkNetResetReq(rb NetworkResetRB) []byte {
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
func MkNetStatusReport(r NetworkStatusData) []byte {
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
		return uint16(LenBool)
	case DEtypeEnum:
		return uint16(LenEnum)
	case DEtypeUint:
		return uint16(LenUint)
	case DEtypeBmap1:
		return uint16(LenBmap1)
	case DEtypeBmap2:
		return uint16(LenBmap2)
	case DEtypeBmap4:
		return uint16(LenBmap4)
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
func MkDeSetBool(g DEGroup, id byte, data byte) []byte {
	d := data
	if d > 1 {
		d = 1
	}
	return MkDES(g, id, DEtypeBool, uint16(LenBool), []byte{d})
}

// Make DE set packet: Enumeration
func MkDeSetEnum(g DEGroup, id byte, data byte) []byte {
	return MkDES(g, id, DEtypeEnum, uint16(LenEnum), []byte{data})
}

// Make DE set packet: Uint/value
func MkDeSetUint(g DEGroup, id byte, data uint32) []byte {
	dbig := []byte{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDES(g, id, DEtypeUint, uint16(LenUint), dbig)
}

// Make DE set packet: 1-byte bitmap
func MkDeSetBmap1(g DEGroup, id byte, data byte) []byte {
	return MkDES(g, id, DEtypeBmap1, uint16(LenBmap1), []byte{data})
}

// Make DE set packet: 2-byte bitmap
func MkDeSetBmap2(g DEGroup, id byte, data uint16) []byte {
	dbig := []byte{}
	dbig = binary.BigEndian.AppendUint16(dbig, data)
	return MkDES(g, id, DEtypeBmap2, uint16(LenBmap2), dbig)
}

// Make DE set packet: 4-byte bitmap
func MkDeSetBmap4(g DEGroup, id byte, data uint32) []byte {
	dbig := []byte{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDES(g, id, DEtypeBmap4, uint16(LenBmap4), dbig)
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
func MkDeRepBool(g DEGroup, id byte, data byte) []byte {
	d := data
	if d > 1 {
		d = 1
	}
	return MkDER(g, id, DEtypeBool, uint16(LenBool), []byte{d})
}

// Make DE report packet: Enumeration
func MkDeRepEnum(g DEGroup, id byte, data byte) []byte {
	return MkDER(g, id, DEtypeEnum, uint16(LenEnum), []byte{data})
}

// Make DE report packet: Uint/value
func MkDeRepUint(g DEGroup, id byte, data uint32) []byte {
	dbig := []byte{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDER(g, id, DEtypeUint, uint16(LenUint), dbig)
}

// Make DE report packet: 1-Byte bitmap
func MkDeRepBmap1(g DEGroup, id byte, data byte) []byte {
	return MkDER(g, id, DEtypeBmap1, uint16(LenBmap1), []byte{data})
}

// Make DE report packet: 2-Byte bitmap
func MkDeRepBmap2(g DEGroup, id byte, data uint16) []byte {
	dbig := []byte{}
	dbig = binary.BigEndian.AppendUint16(dbig, data)
	return MkDER(g, id, DEtypeBmap2, uint16(LenBmap2), dbig)
}

// Make DE report packet: 4-Byte bitmap
func MkDeRepBmap4(g DEGroup, id byte, data uint32) []byte {
	dbig := []byte{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDER(g, id, DEtypeBmap4, uint16(LenBmap4), dbig)
}

// Make DE fault report request packet
func MkDeFaultAllReq() []byte {
	p := Create(CmdDEFault)
	return p.Build().Buf
}

// Make DE fault report packet: No fault on all DE
func MkDeNoFaultAll() []byte {
	p := Create(CmdDEFault)
	p.AppendOne(0)
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

// Parse buffer into base packet
func Parse(buf []byte) (BasePkt, error) {
	if len(buf) < int(PktMinLen) {
		return BasePkt{}, fmt.Errorf("PG buffer is too short")
	}
	if buf[IdxHead1] != Head1 {
		return BasePkt{}, fmt.Errorf("PG header 1 is wrong")
	}
	if buf[IdxHead2] != Head2 {
		return BasePkt{}, fmt.Errorf("PG header 2 is wrong")
	}
	err := ChksumVerify(buf[:len(buf)-1], buf[len(buf)-1])
	if err != nil {
		return BasePkt{}, err
	}

	pkt := BasePkt{Ver: buf[IdxVer], CommandID: CmdID(buf[IdxCmd])}
	dlenSlice := buf[IdxDlen : IdxDlen+DlenLen]
	r := bytes.NewReader(dlenSlice)
	binary.Read(r, binary.BigEndian, &pkt.DataLen)
	if len(buf) != int(PktMinLen)+int(pkt.DataLen) {
		return BasePkt{}, fmt.Errorf("PG packet data length mismatch")
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
		var data uint16
		r := bytes.NewReader(p.DataRaw)
		binary.Read(r, binary.BigEndian, &data)
		return uint32(data)
	} else if p.Dlen == 4 {
		var data uint32
		r := bytes.NewReader(p.DataRaw)
		binary.Read(r, binary.BigEndian, &data)
		return data
	} else {
		return 0
	}
}

// Parse buffer into DE packet
func ParseDEP(buf []byte) (DePkt, error) {
	if len(buf) < int(DEPktMinLen) {
		return DePkt{}, fmt.Errorf("DEP buffer is too short")
	}
	dep := DePkt{}
	dep.Group = DEGroup(buf[IdxDEPGroup])
	dep.Id = buf[IdxDEPID]
	dep.Dtype = DEtype(buf[IdxDEPtype])
	dlenSlice := buf[IdxDEPdlen : IdxDEPdlen+IdxDEPkt(DlenLen)]
	r := bytes.NewReader(dlenSlice)
	binary.Read(r, binary.BigEndian, &dep.Dlen)
	if len(buf) < int(DEPktMinLen)+int(dep.Dlen) {
		return DePkt{}, fmt.Errorf("DEP buffer is shorter than indicated by data length")
	}
	dataSlice := buf[IdxDEPdata : IdxDEPdata+IdxDEPkt(dep.Dlen)]
	dep.DataRaw = append(dep.DataRaw, dataSlice...)
	dep.Buf = buf[:uint16(DEPktMinLen)+dep.Dlen]

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
		return dep, fmt.Errorf("DEP Wrong command ID")
	}
	return ParseDEP(p.Data)
}

// Get schedule list from base packet
func (p BasePkt) GetSchList() ([]SchPkt, error) {
	var err error = nil
	if p.CommandID != CmdSchedule {
		return []SchPkt{}, fmt.Errorf("SCH Wrong command ID")
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
			return []SchPkt{}, fmt.Errorf("%s on schedule with id %d", err.Error(), sch.Id)
		}
		pIdx += int(SchHeadLen) + int(DEPktMinLen) + int(sch.Dep.Dlen)
		if pIdx > int(p.DataLen)+1 {
			return []SchPkt{}, fmt.Errorf("SCH more schedules expected")
		}
	}

	return schList, nil
}
