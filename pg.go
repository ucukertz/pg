// Package pg Implements pg communication protocol
package pg

import (
	"fmt"
	"bytes"
	"encoding/binary"
	"time"
)

// Unbuilt pg packet
type BuildPkt struct {
	ver uint8
	commandID CmdID
	dataLen uint16
	data []uint8
}

// Base pg packet
type BasePkt struct {
	ver uint8
	commandID CmdID
	dataLen uint16
	data []uint8
	buf []uint8
	chksum uint8
}

// DV packet
type DvPkt struct {
	group DVGroup
	id uint8
	dtype DVtype
	dlen uint16
	dataRaw []uint8
	data uint32
	buf []uint8
}

// Schedule packet
type SchPkt struct {
	id uint8
	weekdays uint8
	hour uint8
	minute uint8
	dvp DvPkt
}

var PgVer uint8 = 0 // Active pg version

// Set active pg version
func SetVer(ver uint8) {
	PgVer = ver
}

// Sum of all bytes in slice
func Chksum(buf []uint8) uint8 {
	var chksum uint8 = 0
	for _, b := range buf {
		chksum += b
	}
	return chksum
}

// Verify checksum of buf is the same as chksum
func ChksumVerify(buf []uint8, chksum uint8) error {
	expected := Chksum(buf)
	if chksum == expected {
		return nil
	} else {
		return fmt.Errorf("Got 0x%x but expected 0x%x", chksum, expected)
	}
}

// Create unbuilt packet with cid as Command ID
func Create(cid CmdID) BuildPkt {
	return BuildPkt{ver: PgVer, commandID: cid, dataLen: 0, data: []uint8{}}
}

// Append one byte to unbuilt packet
func (pkt *BuildPkt)AppendOne(data uint8) {
	pkt.dataLen += 1
	pkt.data = append(pkt.data, data)
}

// Append multiple bytes to unbuilt packet
func (pkt *BuildPkt)Append(data []uint8) {
	pkt.dataLen += uint16(len(data))
	pkt.data = append(pkt.data, data...)
}

// Build DV packet from parameters then append it to unbuilt packet
func (pkt *BuildPkt)AppendDVPkt(g DVGroup, id uint8, t DVtype, dlen uint16, data []uint8) {
	pkt.AppendOne(uint8(g))
	pkt.AppendOne(id)
	pkt.AppendOne(uint8(t))
	dlenBig := []uint8{}
	dlenBig = binary.BigEndian.AppendUint16(dlenBig, dlen)
	pkt.Append(dlenBig)
	pkt.Append(data[:dlen])
}

// Build DV packet with fixed data length from parameters then append it to unbuilt packet
func (pkt *BuildPkt)AppendDVPktFixed(g DVGroup, id uint8, t DVtype, dlen uint16, data uint32) {
	dlen = EnforceDVlen(t, dlen)
	pkt.AppendOne(uint8(g))
	pkt.AppendOne(id)
	pkt.AppendOne(uint8(t))
	dlenBig := []uint8{}
	dlenBig = binary.BigEndian.AppendUint16(dlenBig, dlen)
	pkt.Append(dlenBig)
	if dlen == 1 {
		pkt.AppendOne(uint8(data))
	} else if dlen == 2 {
		dataBig := []uint8{}
		dataBig = binary.BigEndian.AppendUint16(dataBig, uint16(data))
		pkt.Append(dataBig)
	} else if dlen == 4 {
		dataBig := []uint8{}
		dataBig = binary.BigEndian.AppendUint32(dataBig, data)
		pkt.Append(dataBig)
	}
}

// Transform unbuilt packet into base packet
func (p BuildPkt)Build() BasePkt {
	Pkt := BasePkt{ver: p.ver, commandID: p.commandID, dataLen: p.dataLen, data: p.data}
	Pkt.buf = []uint8{Head1, Head2, Pkt.ver, uint8(Pkt.commandID)}
	Pkt.buf = binary.BigEndian.AppendUint16(Pkt.buf, Pkt.dataLen)
	Pkt.buf = append(Pkt.buf, Pkt.data...)
	chksum := Chksum(Pkt.buf)
	Pkt.buf = append(Pkt.buf, chksum)
	return Pkt
}

func (p BasePkt)String() string {
	return fmt.Sprintf("ver: %d cmd: %d dlen: %d, data:[0x%x] cs: 0x%x",
	p.ver, p.commandID, p.dataLen, p.data, p.chksum)
}

func (g DVGroup)String() string {
	switch g {
	case DvgInfo: return "Info"
	case DvgSensor: return "Sensor"
	case DvgControl: return "Control"
	default: return "Invalid"
	}
}

func (t DVtype)String() string {
	switch t {
	case DVtypeRaw: return "Raw"
	case DVtypeString: return "String"
	case DVtypeBool: return "Bool"
	case DVtypeEnum: return "Enum"
	case DVtypeUint: return "Uint"
	case DVtypeBmap1: return "Bmap1"
	case DVtypeBmap2: return "Bmap2"
	case DVtypeBmap4: return "Bmap4"
	default: return "Invalid"
	}
}

func (p DvPkt)String() string {
	return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x] data: %d",
	p.group, p.id, p.dtype, p.dlen, p.dataRaw, p.data)
}

func (p SchPkt)String() string {
	return fmt.Sprintf("id: %d wdays: %08b hour: %d minute: %d dvp:[%s]", p.id, p.weekdays, p.hour, p.minute, p.dvp)
}

// Make handshake packet
func MkHandshake(hs Handshake) []uint8 {
	p := Create(CmdHandshake)
	p.AppendOne(uint8(hs))
	return p.Build().buf
}

// Make device info request packet
func MkDevInfoReq(rb DeviceInfoRB) []uint8 {
	p := Create(CmdDeviceInfo)
	p.AppendOne(uint8(rb))
	return p.Build().buf
}

// Make device info response packet
func MkDevInfoResp(rb DeviceInfoRB, resp string) []uint8 {
	p := Create(CmdDeviceInfo)
	p.AppendOne(uint8(rb))
	p.Append([]uint8(resp))
	return p.Build().buf
}

// Make network reset request packet
func MkNetResetReq(rb NetworkResetRB) []uint8 {
	p := Create(CmdNetworkReset)
	p.AppendOne(uint8(rb))
	return p.Build().buf
}

// Make network reset acknowledgement packet
func MkNetResetACK() []uint8 {
	p := Create(CmdNetworkReset)
	return p.Build().buf
}

// Make network status report packet
func MkNetStatusReport(r NetworkStatusData) []uint8 {
	p := Create(CmdNetworkStatus)
	p.AppendOne(uint8(r))
	return p.Build().buf
}

// Make network status report acknowledgement packet
func MkNetStatusReportACK() []uint8 {
	p := Create(CmdNetworkStatus)
	return p.Build().buf
}

// Make time synchronization request packet
func MkTsyncReq(rb TimesyncRB) []uint8 {
	p := Create(CmdTimeSync)
	p.AppendOne(uint8(rb))
	return p.Build().buf
}

// Make time synchronization response packet
func MkTsyncResp(rb TimesyncRB, tm time.Time) []uint8 {
	p := Create(CmdTimeSync)
	p.AppendOne(uint8(rb))
	p.AppendOne(uint8(tm.Year()-100))
	p.AppendOne(uint8(tm.Month()))
	p.AppendOne(uint8(tm.Day()))
	p.AppendOne(uint8(tm.Weekday()))
	p.AppendOne(uint8(tm.Hour()))
	p.AppendOne(uint8(tm.Minute()))
	p.AppendOne(uint8(tm.Second()))
	return p.Build().buf
}

// Make DV reset request packet
func MkDvResetAllReq() []uint8 {
	p := Create(CmdDVSet)
	return p.Build().buf
}

// Enforce DV data length for DV data types with fixed length
func EnforceDVlen(t DVtype, dlen uint16) uint16 {
	switch t {
	case DVtypeBool: return uint16(LenBool)
	case DVtypeEnum: return uint16(LenEnum)
	case DVtypeUint: return uint16(LenUint)
	case DVtypeBmap1: return uint16(LenBmap1)
	case DVtypeBmap2: return uint16(LenBmap2)
	case DVtypeBmap4: return uint16(LenBmap4)
	default: return dlen 
	}
}

// Make DV set packet
func MkDVS(g DVGroup, id uint8, t DVtype, dlen uint16, data []uint8) []uint8 {
	p := Create(CmdDVSet)
	dlen = EnforceDVlen(t, dlen)
	p.AppendDVPkt(g, id, t, dlen, data)
	return p.Build().buf
}


// Make DV set packet: Raw
func MkDvSetRaw(g DVGroup, id uint8, data []uint8) []uint8 {
	return MkDVS(g, id, DVtypeRaw, uint16(len(data)), data)
}

// Make DV set packet: String
func MkDvSetStr(g DVGroup, id uint8, data string) []uint8 {
	return MkDVS(g, id, DVtypeString, uint16(len(data)), []uint8(data))
}

// Make DV set packet: Boolean
func MkDvSetBool(g DVGroup, id uint8, data uint8) []uint8 {
	d := data
	if d > 1 {
		d = 1
	}
	return MkDVS(g, id, DVtypeBool, uint16(LenBool), []uint8{d})
}

// Make DV set packet: Enumeration
func MkDvSetEnum(g DVGroup, id uint8, data uint8) []uint8 {
	return MkDVS(g, id, DVtypeEnum, uint16(LenEnum), []uint8{data})
}

// Make DV set packet: Uint/value
func MkDvSetUint(g DVGroup, id uint8, data uint32) []uint8 {
	dbig := []uint8{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDVS(g, id, DVtypeUint, uint16(LenUint), dbig)
}

// Make DV set packet: 1-byte bitmap
func MkDvSetBmap1(g DVGroup, id uint8, data uint8) []uint8 {
	return MkDVS(g, id, DVtypeBmap1, uint16(LenBmap1), []uint8{data})
}

// Make DV set packet: 2-byte bitmap
func MkDvSetBmap2(g DVGroup, id uint8, data uint16) []uint8 {
	dbig := []uint8{}
	dbig = binary.BigEndian.AppendUint16(dbig, data)
	return MkDVS(g, id, DVtypeBmap2, uint16(LenBmap2), dbig)
}

// Make DV set packet: 4-byte bitmap
func MkDvSetBmap4(g DVGroup, id uint8, data uint32) []uint8 {
	dbig := []uint8{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDVS(g, id, DVtypeBmap4, uint16(LenBmap4), dbig)
}

// Make DV report packet
func MkDVR(g DVGroup, id uint8, t DVtype, dlen uint16, data []uint8) []uint8 {
	p := Create(CmdDVReport)
	dlen = EnforceDVlen(t, dlen)
	p.AppendDVPkt(g, id, t, dlen, data)
	return p.Build().buf
}

// Make DV report packet: Raw
func MkDvRepRaw(g DVGroup, id uint8, data []uint8) []uint8 {
	return MkDVR(g, id, DVtypeRaw, uint16(len(data)), data)
}

// Make DV report packet: String
func MkDvRepStr(g DVGroup, id uint8, data string) []uint8 {
	return MkDVR(g, id, DVtypeString, uint16(len(data)), []uint8(data))
}

// Make DV report packet: Boolean
func MkDvRepBool(g DVGroup, id uint8, data uint8) []uint8 {
	d := data
	if d > 1 {
		d = 1
	}
	return MkDVR(g, id, DVtypeBool, uint16(LenBool), []uint8{d})
}

// Make DV report packet: Enumeration
func MkDvRepEnum(g DVGroup, id uint8, data uint8) []uint8 {
	return MkDVR(g, id, DVtypeEnum, uint16(LenEnum), []uint8{data})
}

// Make DV report packet: Uint/value
func MkDvRepUint(g DVGroup, id uint8, data uint32) []uint8 {
	dbig := []uint8{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDVR(g, id, DVtypeUint, uint16(LenUint), dbig)
}

// Make DV report packet: 1-Byte bitmap
func MkDvRepBmap1(g DVGroup, id uint8, data uint8) []uint8 {
	return MkDVR(g, id, DVtypeBmap1, uint16(LenBmap1), []uint8{data})
}

// Make DV report packet: 2-Byte bitmap
func MkDvRepBmap2(g DVGroup, id uint8, data uint16) []uint8 {
	dbig := []uint8{}
	dbig = binary.BigEndian.AppendUint16(dbig, data)
	return MkDVR(g, id, DVtypeBmap2, uint16(LenBmap2), dbig)
}

// Make DV report packet: 4-Byte bitmap
func MkDvRepBmap4(g DVGroup, id uint8, data uint32) []uint8 {
	dbig := []uint8{}
	dbig = binary.BigEndian.AppendUint32(dbig, data)
	return MkDVR(g, id, DVtypeBmap4, uint16(LenBmap4), dbig)
}

// Make DV fault report request packet 
func MkDvFaultAllReq() []uint8 {
	p := Create(CmdDVFault)
	return p.Build().buf
}

// Make DV fault report packet: No fault on all DV 
func MkDvNoFaultAll() []uint8 {
	p := Create(CmdDVFault)
	p.AppendOne(0)
	return p.Build().buf
}

// Make DV fault report packet
func MkDvFaultRep(g DVGroup, id uint8, f DVfault) []uint8 {
	p := Create(CmdDVFault)
	p.AppendOne(uint8(g))
	p.AppendOne(id)
	p.AppendOne(uint8(f))
	return p.Build().buf
}

// Make schedule clear request packet
func MkSchEraseAllReq() []uint8 {
	p := Create(CmdSchedule)
	return p.Build().buf
}

// Make schedule execution report packet
func MkSchExecReport(schId uint8) []uint8 {
	p := Create(CmdSchedule)
	p.AppendOne(schId)
	return p.Build().buf
}

// Make schedule set packet
func MkSchSet(schList []SchPkt) []uint8 {
	p := Create(CmdSchedule)
	p.AppendOne(uint8(len(schList)))
	for _, sch := range schList {
		p.AppendOne(sch.id)
		p.AppendOne(sch.weekdays)
		p.AppendOne(sch.hour)
		p.AppendOne(sch.minute)
		dvp := sch.dvp
		if (sch.dvp.dtype != DVtypeRaw && sch.dvp.dtype != DVtypeString) {
			p.AppendDVPktFixed(dvp.group, dvp.id, dvp.dtype, dvp.dlen, dvp.data)
		} else {
			p.AppendDVPkt(dvp.group, dvp.id, dvp.dtype, dvp.dlen, dvp.dataRaw)
		}
	}
	return p.Build().buf
}

// Parse buffer into base packet
func Parse(buf []uint8) (BasePkt, error) {
	if (len(buf) < int(PktMinLen)) {
		return BasePkt{}, fmt.Errorf("Base: Buffer is too short")
	}
	if (buf[IdxHead1] != Head1) {
		return BasePkt{}, fmt.Errorf("Header 1 is wrong")
	} 
	if (buf[IdxHead2] != Head2) {
		return BasePkt{}, fmt.Errorf("Header 2 is wrong")
	}
	err := ChksumVerify(buf[:len(buf)-1], buf[len(buf)-1])
	if (err != nil) {
		return BasePkt{}, err
	}

	pkt := BasePkt{ver: buf[IdxVer], commandID: CmdID(buf[IdxCmd])}
	dlenSlice := buf[IdxDlen:IdxDlen+IdxBasePkt(DlenLen)]
	r := bytes.NewReader(dlenSlice)
	binary.Read(r, binary.BigEndian, &pkt.dataLen)
	pkt.data = buf[IdxData:IdxData+IdxBasePkt(pkt.dataLen)]
	pkt.buf = append(pkt.buf, buf...)
	pkt.chksum = buf[len(buf)-1]

	return pkt, nil
}

// Get numeric data from DV packet with fixed-length data type
func DvpFixedData(p DvPkt) uint32 {
	if p.dlen == 1 {
		return uint32(p.dataRaw[0])
	} else if p.dlen == 2 {
		var data uint16
		r := bytes.NewReader(p.dataRaw)
		binary.Read(r, binary.BigEndian, &data)
		return uint32(data)
	} else if p.dlen == 4 {
		var data uint32
		r := bytes.NewReader(p.dataRaw)
		binary.Read(r, binary.BigEndian, &data)
		return data
	} else {
		return 0
	}
}

// Parse buffer into DV packet
func ParseDVP(buf []uint8) DvPkt {
	dvp := DvPkt{}
	dvp.group = DVGroup(buf[IdxDVPGroup])
	dvp.id = buf[IdxDVPID]
	dvp.dtype = DVtype(buf[IdxDVPtype])
	dlenSlice := buf[IdxDVPdlen:IdxDVPdlen+IdxDVPkt(DlenLen)]
	r := bytes.NewReader(dlenSlice)
	binary.Read(r, binary.BigEndian, &dvp.dlen)
	dataSlice := buf[IdxDVPdata:IdxDVPdata+IdxDVPkt(dvp.dlen)]
	dvp.dataRaw = append(dvp.dataRaw, dataSlice...)
	dvp.buf = buf[:DVPktMinLen+uint8(dvp.dlen)]

	if (dvp.dtype != DVtypeRaw && dvp.dtype != DVtypeString) {
		dvp.data = DvpFixedData(dvp)
	} else { 
		dvp.data = 0 
	}
	return dvp
}

// Get DV packet from base packet
// Can only be used when base packet data contains only and exclusively one DV packet
func (p BasePkt)GetDVP() (DvPkt, error) {
	dvp := DvPkt{}
	if (len(p.data) < int(DVPktMinLen)) {
		return dvp, fmt.Errorf("DVP: Buffer is too short")
	}
	if (p.commandID != CmdDVSet && p.commandID != CmdDVReport) {
		return dvp, fmt.Errorf("DVP: Wrong command ID")
	}
	return ParseDVP(p.data), nil
}

// Get schedule list from base packet
func (p BasePkt)GetSchList() ([]SchPkt, error) {
	if (p.commandID != CmdSchedule) {
		return []SchPkt{}, fmt.Errorf("SCH: Wrong command ID")
	}

	schNum := p.data[0]
	schList := make([]SchPkt, schNum)
	pIdx := 1
	for i := range schList {
		schList[i].id = p.data[pIdx+int(IdxSchpID)]
		schList[i].weekdays = p.data[pIdx+int(IdxSchpWday)]
		schList[i].hour = p.data[pIdx+int(IdxSchpHour)]
		schList[i].minute = p.data[pIdx+int(IdxSchpMinute)]
		schList[i].dvp = ParseDVP(p.data[pIdx+int(IdxSchpDvp):])
		pIdx += int(SchHeadLen)+int(DVPktMinLen)+int(schList[i].dvp.dlen)
		if (pIdx > int(p.dataLen)+1) {
			return []SchPkt{}, fmt.Errorf("More schedules expected")
		}
	}

	return schList, nil
}