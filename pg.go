// Implements pg protocol
package pg

import (
	"fmt"
	"bytes"
	"encoding/binary"
	"time"
)

// Unbuilt pg packet
type BuildPkt struct {
	Ver uint8
	CommandID CmdID
	DataLen uint16
	Data []uint8
}

// Base pg packet
type BasePkt struct {
	Ver uint8
	CommandID CmdID
	DataLen uint16
	Data []uint8
	Buf []uint8
	Chksum uint8
}

// DV packet
type DvPkt struct {
	Group DVGroup
	Id uint8
	Dtype DVtype
	Dlen uint16
	DataRaw []uint8
	Data uint32
	Buf []uint8
}

// Schedule packet
type SchPkt struct {
	Id uint8
	Weekdays uint8
	Hour uint8
	Minute uint8
	Dvp DvPkt
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
	return BuildPkt{Ver: PgVer, CommandID: cid, DataLen: 0, Data: []uint8{}}
}

// Append one byte to unbuilt packet
func (pkt *BuildPkt)AppendOne(data uint8) {
	pkt.DataLen += 1
	pkt.Data = append(pkt.Data, data)
}

// Append multiple bytes to unbuilt packet
func (pkt *BuildPkt)Append(data []uint8) {
	pkt.DataLen += uint16(len(data))
	pkt.Data = append(pkt.Data, data...)
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
	Pkt := BasePkt{Ver: p.Ver, CommandID: p.CommandID, DataLen: p.DataLen, Data: p.Data}
	Pkt.Buf = []uint8{Head1, Head2, Pkt.Ver, Pkt.CommandID}
	Pkt.Buf = binary.BigEndian.AppendUint16(Pkt.Buf, Pkt.DataLen)
	Pkt.Buf = append(Pkt.Buf, Pkt.Data...)
	chksum := Chksum(Pkt.Buf)
	Pkt.Buf = append(Pkt.Buf, chksum)
	return Pkt
}

func (p BasePkt)String() string {
	return fmt.Sprintf("ver: %d cmd: %d dlen: %d, data:[0x%x] cs: 0x%x",
	p.Ver, p.CommandID, p.DataLen, p.Data, p.Chksum)
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
	switch (p.Dtype) {
	case DVtypeRaw:
		return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x]",
		p.Group, p.Id, p.Dtype, p.Dlen, p.DataRaw)
	case DVtypeString:
		return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x] data: %s",
		p.Group, p.Id, p.Dtype, p.Dlen, p.DataRaw, p.DataRaw)
	default:
		return fmt.Sprintf("group: %s id: %d dtype: %s dlen: %d dataRaw:[0x%x] data: %d",
		p.Group, p.Id, p.Dtype, p.Dlen, p.DataRaw, p.Data)
	}
}

func (p SchPkt)String() string {
	return fmt.Sprintf("id: %d wdays: %08b hour: %d minute: %d dvp:[%s]", p.Id, p.Weekdays, p.Hour, p.Minute, p.Dvp)
}

// Make handshake packet
func MkHandshake(hs Handshake) []uint8 {
	p := Create(CmdHandshake)
	p.AppendOne(hs)
	return p.Build().Buf
}

// Make device info request packet
func MkDevInfoReq(rb DeviceInfoRB) []uint8 {
	p := Create(CmdDeviceInfo)
	p.AppendOne(rb)
	return p.Build().Buf
}

// Make device info response packet
func MkDevInfoResp(rb DeviceInfoRB, resp string) []uint8 {
	p := Create(CmdDeviceInfo)
	p.AppendOne(rb)
	p.Append([]uint8(resp))
	return p.Build().Buf
}

// Make network reset request packet
func MkNetResetReq(rb NetworkResetRB) []uint8 {
	p := Create(CmdNetworkReset)
	p.AppendOne(rb)
	return p.Build().Buf
}

// Make network reset acknowledgement packet
func MkNetResetACK() []uint8 {
	p := Create(CmdNetworkReset)
	return p.Build().Buf
}

// Make network status report packet
func MkNetStatusReport(r NetworkStatusData) []uint8 {
	p := Create(CmdNetworkStatus)
	p.AppendOne(r)
	return p.Build().Buf
}

// Make network status report acknowledgement packet
func MkNetStatusReportACK() []uint8 {
	p := Create(CmdNetworkStatus)
	return p.Build().Buf
}

// Make time synchronization request packet
func MkTsyncReq(rb TimesyncRB) []uint8 {
	p := Create(CmdTimeSync)
	p.AppendOne(rb)
	return p.Build().Buf
}

// Make time synchronization response packet
func MkTsyncResp(rb TimesyncRB, tm time.Time) []uint8 {
	p := Create(CmdTimeSync)
	p.AppendOne(rb)
	p.AppendOne(uint8(tm.Year()-100))
	p.AppendOne(uint8(tm.Month()))
	p.AppendOne(uint8(tm.Day()))
	p.AppendOne(uint8(tm.Weekday()))
	p.AppendOne(uint8(tm.Hour()))
	p.AppendOne(uint8(tm.Minute()))
	p.AppendOne(uint8(tm.Second()))
	return p.Build().Buf
}

// Make DV reset request packet
func MkDvResetAllReq() []uint8 {
	p := Create(CmdDVSet)
	return p.Build().Buf
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
	return p.Build().Buf
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
	return p.Build().Buf
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
	return p.Build().Buf
}

// Make DV fault report packet: No fault on all DV 
func MkDvNoFaultAll() []uint8 {
	p := Create(CmdDVFault)
	p.AppendOne(0)
	return p.Build().Buf
}

// Make DV fault report packet
func MkDvFaultRep(g DVGroup, id uint8, f DVfault) []uint8 {
	p := Create(CmdDVFault)
	p.AppendOne(uint8(g))
	p.AppendOne(id)
	p.AppendOne(f)
	return p.Build().Buf
}

// Make schedule clear request packet
func MkSchEraseAllReq() []uint8 {
	p := Create(CmdSchedule)
	return p.Build().Buf
}

// Make schedule execution report packet
func MkSchExecReport(schId uint8) []uint8 {
	p := Create(CmdSchedule)
	p.AppendOne(schId)
	return p.Build().Buf
}

// Make schedule set packet
func MkSchSet(schList []SchPkt) []uint8 {
	p := Create(CmdSchedule)
	p.AppendOne(uint8(len(schList)))
	for _, sch := range schList {
		p.AppendOne(sch.Id)
		p.AppendOne(sch.Weekdays)
		p.AppendOne(sch.Hour)
		p.AppendOne(sch.Minute)
		dvp := sch.Dvp
		if (sch.Dvp.Dtype != DVtypeRaw && sch.Dvp.Dtype != DVtypeString) {
			p.AppendDVPktFixed(dvp.Group, dvp.Id, dvp.Dtype, dvp.Dlen, dvp.Data)
		} else {
			p.AppendDVPkt(dvp.Group, dvp.Id, dvp.Dtype, dvp.Dlen, dvp.DataRaw)
		}
	}
	return p.Build().Buf
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

	pkt := BasePkt{Ver: buf[IdxVer], CommandID: CmdID(buf[IdxCmd])}
	dlenSlice := buf[IdxDlen:IdxDlen+IdxBasePkt(DlenLen)]
	r := bytes.NewReader(dlenSlice)
	binary.Read(r, binary.BigEndian, &pkt.DataLen)
	pkt.Data = buf[IdxData:IdxData+IdxBasePkt(pkt.DataLen)]
	pkt.Buf = append(pkt.Buf, buf...)
	pkt.Chksum = buf[len(buf)-1]

	return pkt, nil
}

// Get numeric data from DV packet with fixed-length data type
func DvpFixedData(p DvPkt) uint32 {
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

// Parse buffer into DV packet
func ParseDVP(buf []uint8) DvPkt {
	dvp := DvPkt{}
	dvp.Group = DVGroup(buf[IdxDVPGroup])
	dvp.Id = buf[IdxDVPID]
	dvp.Dtype = DVtype(buf[IdxDVPtype])
	dlenSlice := buf[IdxDVPdlen:IdxDVPdlen+IdxDVPkt(DlenLen)]
	r := bytes.NewReader(dlenSlice)
	binary.Read(r, binary.BigEndian, &dvp.Dlen)
	dataSlice := buf[IdxDVPdata:IdxDVPdata+IdxDVPkt(dvp.Dlen)]
	dvp.DataRaw = append(dvp.DataRaw, dataSlice...)
	dvp.Buf = buf[:uint16(DVPktMinLen)+dvp.Dlen]

	if (dvp.Dtype != DVtypeRaw && dvp.Dtype != DVtypeString) {
		dvp.Data = DvpFixedData(dvp)
	} else { 
		dvp.Data = 0 
	}
	return dvp
}

// Get DV packet from base packet
// Can only be used when base packet data contains only and exclusively one DV packet
func (p BasePkt)GetDVP() (DvPkt, error) {
	dvp := DvPkt{}
	if (len(p.Data) < int(DVPktMinLen)) {
		return dvp, fmt.Errorf("DVP: Buffer is too short")
	}
	if (p.CommandID != CmdDVSet && p.CommandID != CmdDVReport) {
		return dvp, fmt.Errorf("DVP: Wrong command ID")
	}
	return ParseDVP(p.Data), nil
}

// Get schedule list from base packet
func (p BasePkt)GetSchList() ([]SchPkt, error) {
	if (p.CommandID != CmdSchedule) {
		return []SchPkt{}, fmt.Errorf("SCH: Wrong command ID")
	}

	schNum := p.Data[0]
	schList := make([]SchPkt, schNum)
	pIdx := 1
	for i := range schList {
		schList[i].Id = p.Data[pIdx+int(IdxSchpID)]
		schList[i].Weekdays = p.Data[pIdx+int(IdxSchpWday)]
		schList[i].Hour = p.Data[pIdx+int(IdxSchpHour)]
		schList[i].Minute = p.Data[pIdx+int(IdxSchpMinute)]
		schList[i].Dvp = ParseDVP(p.Data[pIdx+int(IdxSchpDvp):])
		pIdx += int(SchHeadLen)+int(DVPktMinLen)+int(schList[i].Dvp.Dlen)
		if (pIdx > int(p.DataLen)+1) {
			return []SchPkt{}, fmt.Errorf("More schedules expected")
		}
	}

	return schList, nil
}