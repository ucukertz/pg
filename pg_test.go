package pg

import (
	"testing"
	"math"
)

func TestPgMk(t *testing.T) {
	SetVer(0)
	buf := MkHandshake(HeartbeatACK)
	t.Logf("0: %x", buf)
	p, err := Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p0: %s", p)

	buf = MkDevInfoReq(DeviceName)
	t.Logf("1-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p1-1: %s", p)

	buf = MkDevInfoResp(DeviceName, "genericdevice")
	t.Logf("1-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p1-2: %s data: %s", p, p.data)

	buf = MkNetResetReq(NetSC)
	t.Logf("2-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p2-1: %s", p)

	buf = MkNetResetACK()
	t.Logf("2-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p2-1: %s", p)

	buf = MkNetStatusReport(NetCloudNG)
	t.Logf("3-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p3-1: %s", p)

	buf = MkNetStatusReportACK()
	t.Logf("3-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p3-2: %s", p)

	d := "abc-test-cba"
	buf = MkDVS(DvgControl, 2, DVtypeRaw, uint16(len(d)), []uint8(d))
	t.Logf("5-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-1: %s", p)

	dvp, err := p.GetDVP()
	t.Logf("dvp5-1: %s", dvp)

	buf = MkDvSetRaw(DvgInfo, 1, []uint8(d))
	t.Logf("5-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-2: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-2: %s data: %s", dvp, dvp.dataRaw)

	buf = MkDvSetStr(DvgSensor, 0, d)
	t.Logf("5-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-3: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-3: %s data: %s", dvp, dvp.dataRaw)

	buf = MkDvSetBool(DvgControl, 255, 100 /* Intentional */)
	t.Logf("5-4: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-4: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-4: %s", dvp)

	buf = MkDvSetEnum(DvgInfo, 254, 100)
	t.Logf("5-5: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-5: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-5: %s", dvp)

	buf = MkDvSetUint(DvgControl, 253, math.MaxUint32-1)
	t.Logf("5-6: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-6: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-6: %s", dvp)

	buf = MkDvSetBmap1(DvgSensor, 252, math.MaxUint8-2)
	t.Logf("5-7: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-7: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-7: %s", dvp)

	buf = MkDvSetBmap2(DvgSensor, 251, math.MaxUint16-3)
	t.Logf("5-8: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-8: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-8: %s", dvp)

	buf = MkDvSetBmap4(DvgSensor, 250, math.MaxUint32-4)
	t.Logf("5-9: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-9: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp5-9: %s", dvp)

	buf = MkDVR(DvgControl, 2, DVtypeRaw, uint16(len(d)), []uint8(d))
	t.Logf("6-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-1: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-1: %s", dvp)

	buf = MkDvRepRaw(DvgInfo, 1, []uint8(d))
	t.Logf("6-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-2: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-2: %s data: %s", dvp, dvp.dataRaw)

	buf = MkDvRepStr(DvgSensor, 0, d)
	t.Logf("6-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-3: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-3: %s data: %s", dvp, dvp.dataRaw)

	buf = MkDvRepBool(DvgControl, 255, 100 /* Intentional */)
	t.Logf("6-4: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-4: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-4: %s", dvp)

	buf = MkDvRepEnum(DvgInfo, 254, 100)
	t.Logf("6-5: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-5: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-5: %s", dvp)

	buf = MkDvRepUint(DvgControl, 253, math.MaxUint32-1)
	t.Logf("6-6: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-6: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-6: %s", dvp)

	buf = MkDvRepBmap1(DvgSensor, 252, math.MaxUint8-2)
	t.Logf("6-7: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-7: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-7: %s", dvp)

	buf = MkDvRepBmap2(DvgInfo, 251, math.MaxUint16-3)
	t.Logf("6-8: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-8: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-8: %s", dvp)

	buf = MkDvRepBmap4(DvgControl, 250, math.MaxUint32-4)
	t.Logf("6-9: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-9: %s", p)

	dvp, err = p.GetDVP()
	t.Logf("dvp6-9: %s", dvp)

	buf = MkDvFaultAllReq()
	t.Logf("7-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p7-1: %s", p)

	buf = MkDvNoFaultAll()
	t.Logf("7-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p7-2: %s", p)

	buf = MkDvFaultRep(DvgSensor, 0, DvfMalformed)
	t.Logf("7-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p7-3: %s", p)

	sch := make([]SchPkt, 2)
	sch[0].id = 0
	sch[0].weekdays = 0b01000000
	sch[0].hour = 23
	sch[0].minute = 59
	sch[0].dvp.group = DvgControl
	sch[0].dvp.id = 255
	sch[0].dvp.dtype = DVtypeString
	sch[0].dvp.dlen = uint16(len(d))
	sch[0].dvp.dataRaw = []uint8(d)

	sch[1].id = 1
	sch[1].weekdays = 0b00010010
	sch[1].hour = 22
	sch[1].minute = 58
	sch[1].dvp.group = DvgControl
	sch[1].dvp.id = 254
	sch[1].dvp.dtype = DVtypeUint
	sch[1].dvp.data = math.MaxUint32-1

	buf = MkSchSet(sch)
	t.Logf("8-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p8-1: %s", p)

	pSch, err := p.GetSchList()
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("sch8-1: %s", pSch)
	}
}