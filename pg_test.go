package pg

import (
	"testing"
	"math"
)

func TestPgMk(t *testing.T) {
	SetVer(0)
	buf := MkHandshakeEnd()
	t.Logf("0-1: %x", buf)
	p, err := Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p0-1: %s", p)

	buf = MkHandshake(HeartbeatACK)
	t.Logf("0-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p0-2: %s", p)

	buf = MkUinfoReqAll()
	t.Logf("1-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p1-1: %s", p)

	buf = MkUinfoReq(DeviceName)
	t.Logf("1-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p1-2: %s", p)

	buf = MkUinfoResp(DeviceName, "genericdevice")
	t.Logf("1-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p1-3: %s data: %s", p, p.Data)

	buf = MkNetResetReq(NetQC)
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
	t.Logf("p2-2: %s", p)

	buf = MkNetStatusReport(NetUplinkNG)
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

	buf = MkTsyncNotReady()
	t.Logf("4-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p4-1: %s", p)

	d := "abc-test-cba"
	buf = MkDES(DegControl, 2, DEtypeRaw, uint16(len(d)), []uint8(d))
	t.Logf("5-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-1: %s", p)

	dep, err := p.GetDEP()
	t.Logf("dep5-1: %s", dep)

	buf = MkDeSetRaw(DegInfo, 1, []uint8(d))
	t.Logf("5-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-2: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-2: %s", dep)

	buf = MkDeSetStr(DegSensor, 0, d)
	t.Logf("5-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-3: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-3: %s", dep)

	buf = MkDeSetBool(DegControl, 255, 100 /* Intentional */)
	t.Logf("5-4: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-4: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-4: %s", dep)

	buf = MkDeSetEnum(DegInfo, 254, 100)
	t.Logf("5-5: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-5: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-5: %s", dep)

	buf = MkDeSetUint(DegControl, 253, math.MaxUint32-1)
	t.Logf("5-6: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-6: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-6: %s", dep)

	buf = MkDeSetBmap1(DegSensor, 252, math.MaxUint8-2)
	t.Logf("5-7: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-7: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-7: %s", dep)

	buf = MkDeSetBmap2(DegSensor, 251, math.MaxUint16-3)
	t.Logf("5-8: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-8: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-8: %s", dep)

	buf = MkDeSetBmap4(DegSensor, 250, math.MaxUint32-4)
	t.Logf("5-9: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p5-9: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep5-9: %s", dep)

	buf = MkDER(DegControl, 2, DEtypeRaw, uint16(len(d)), []uint8(d))
	t.Logf("6-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-1: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-1: %s", dep)

	buf = MkDeRepRaw(DegInfo, 1, []uint8(d))
	t.Logf("6-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-2: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-2: %s", dep)

	buf = MkDeRepStr(DegSensor, 0, d)
	t.Logf("6-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-3: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-3: %s", dep)

	buf = MkDeRepBool(DegControl, 255, 100 /* Intentional */)
	t.Logf("6-4: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-4: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-4: %s", dep)

	buf = MkDeRepEnum(DegInfo, 254, 100)
	t.Logf("6-5: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-5: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-5: %s", dep)

	buf = MkDeRepUint(DegControl, 253, math.MaxUint32-1)
	t.Logf("6-6: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-6: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-6: %s", dep)

	buf = MkDeRepBmap1(DegSensor, 252, math.MaxUint8-2)
	t.Logf("6-7: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-7: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-7: %s", dep)

	buf = MkDeRepBmap2(DegInfo, 251, math.MaxUint16-3)
	t.Logf("6-8: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-8: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-8: %s", dep)

	buf = MkDeRepBmap4(DegControl, 250, math.MaxUint32-4)
	t.Logf("6-9: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p6-9: %s", p)

	dep, err = p.GetDEP()
	t.Logf("dep6-9: %s", dep)

	buf = MkDeFaultAllReq()
	t.Logf("7-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p7-1: %s", p)

	buf = MkDeNoFaultAll()
	t.Logf("7-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p7-2: %s", p)

	buf = MkDeFaultRep(DegSensor, 0, DefMalformed)
	t.Logf("7-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p7-3: %s", p)

	buf = MkSchEraseAllReq()
	t.Logf("8-1: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p8-1: %s", p)

	buf = MkSchExecReport(15)
	t.Logf("8-2: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p8-2: %s", p)

	sch := make([]SchPkt, 2)
	sch[0].Id = 0
	sch[0].Weekdays = 0b01000000
	sch[0].Hour = 23
	sch[0].Minute = 59
	sch[0].Dep.Group = DegControl
	sch[0].Dep.Id = 255
	sch[0].Dep.Dtype = DEtypeString
	sch[0].Dep.Dlen = uint16(len(d))
	sch[0].Dep.DataRaw = []uint8(d)

	sch[1].Id = 1
	sch[1].Weekdays = 0b00010010
	sch[1].Hour = 22
	sch[1].Minute = 58
	sch[1].Dep.Group = DegControl
	sch[1].Dep.Id = 254
	sch[1].Dep.Dtype = DEtypeUint
	sch[1].Dep.Data = math.MaxUint32-1

	buf = MkSchSet(sch)
	t.Logf("8-3: %x", buf)
	p, err = Parse(buf)
	if err != nil {
		t.Error(err)
	}
	t.Logf("p8-3: %s", p)

	pSch, err := p.GetSchList()
	if err != nil {
		t.Error(err)
	} else {
		t.Logf("sch8-3: %s", pSch)
	}
}