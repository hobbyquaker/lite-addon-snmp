package hostmib

import (
	"strings"
	"syscall"
	"time"

	"github.com/hobbyquaker/lite-addon-snmp/internal/mib"
	"github.com/hobbyquaker/lite-addon-snmp/internal/snmp"
)

// System is what the system group says beyond /proc: the configured strings and the agent's own
// identity.
type System struct {
	Name, Location, Contact string
}

// Host registers the standard MIBs.
type Host struct {
	FS      FS
	Sampler *Sampler
	// Config answers sysName, sysLocation and sysContact (sysName "" means the hostname).
	Config func() System
	// ObjectID is sysObjectID.
	ObjectID snmp.OID
	// Started is the agent's start, for sysUpTime.
	Started time.Time
	// ORs are the sysORTable's entries.
	ORs []OR
	// Statfs is syscall.Statfs; the tests replace it.
	Statfs func(string, *syscall.Statfs_t) error
	Now    func() time.Time
}

// OR is one sysORTable row.
type OR struct {
	ID    snmp.OID
	Descr string
}

var (
	oidSystem = snmp.MustOID("1.3.6.1.2.1.1")
	oidIf     = snmp.MustOID("1.3.6.1.2.1.2")
	oidIfX    = snmp.MustOID("1.3.6.1.2.1.31")
	oidEther  = snmp.MustOID("1.3.6.1.2.1.10.7")
	oidHR     = snmp.MustOID("1.3.6.1.2.1.25")
	oidUCD    = snmp.MustOID("1.3.6.1.4.1.2021")
)

// Register adds the modules to a tree.
func (h *Host) Register(t *mib.Tree) {
	if h.Statfs == nil {
		h.Statfs = syscall.Statfs
	}
	if h.Now == nil {
		h.Now = time.Now
	}
	t.Register(mib.FromFunc(mib.Func{OID: oidSystem, Collect: h.system}))
	t.Register(mib.FromFunc(mib.Func{OID: oidIf, MaxAge: 2 * time.Second, Collect: h.ifTable}))
	t.Register(mib.FromFunc(mib.Func{OID: oidIfX, MaxAge: 2 * time.Second, Collect: h.ifXTable}))
	t.Register(mib.FromFunc(mib.Func{OID: oidEther, MaxAge: 10 * time.Second, Collect: h.etherLike}))
	t.Register(mib.FromFunc(mib.Func{OID: oidHR, MaxAge: 5 * time.Second, Collect: h.hostResources}))
	t.Register(mib.FromFunc(mib.Func{OID: oidUCD, MaxAge: 5 * time.Second, Collect: h.ucd}))
}

// SysDescr is net-snmp's sysDescr: uname's sysname, nodename, release, version and machine.
func SysDescr() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return "Linux"
	}
	return strings.Join([]string{cstr(u.Sysname[:]), cstr(u.Nodename[:]), cstr(u.Release[:]), cstr(u.Version[:]), cstr(u.Machine[:])}, " ")
}

// Hostname is uname's nodename.
func Hostname() string {
	var u syscall.Utsname
	if syscall.Uname(&u) != nil {
		return ""
	}
	return cstr(u.Nodename[:])
}

func cstr[T int8 | uint8](b []T) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

type vbs []snmp.VarBind

func (l *vbs) add(o snmp.OID, v snmp.Value) { *l = append(*l, snmp.VarBind{OID: o, Value: v}) }

func (h *Host) uptimeTicks() uint64 {
	return uint64(h.Now().Sub(h.Started) / (10 * time.Millisecond))
}

func (h *Host) system() []snmp.VarBind {
	c := h.Config()
	if c.Name == "" {
		c.Name = Hostname()
	}
	var l vbs
	s := oidSystem
	l.add(s.Append(1, 0), snmp.String(SysDescr()))
	l.add(s.Append(2, 0), snmp.ObjectID(h.ObjectID))
	l.add(s.Append(3, 0), snmp.TimeTicks(h.uptimeTicks()))
	l.add(s.Append(4, 0), snmp.String(c.Contact))
	l.add(s.Append(5, 0), snmp.String(c.Name))
	l.add(s.Append(6, 0), snmp.String(c.Location))
	l.add(s.Append(7, 0), snmp.Integer(72))
	l.add(s.Append(8, 0), snmp.TimeTicks(0))
	for i, or := range h.ORs {
		n := uint32(i + 1)
		l.add(s.Append(9, 1, 2, n), snmp.ObjectID(or.ID))
		l.add(s.Append(9, 1, 3, n), snmp.String(or.Descr))
		l.add(s.Append(9, 1, 4, n), snmp.TimeTicks(0))
	}
	return l
}

func c32(v uint64) snmp.Value { return snmp.Counter32(v) }

func (h *Host) ifTable() []snmp.VarBind {
	ifs := h.FS.ReadNetIfs()
	dev := h.FS.ReadNetDev()
	var l vbs
	l.add(oidIf.Append(1, 0), snmp.Integer(int64(len(ifs))))
	e := oidIf.Append(2, 1)
	for _, n := range ifs {
		i := uint32(n.Index)
		d := dev[n.Name]
		speed := uint64(0)
		if n.SpeedMb > 0 {
			speed = uint64(n.SpeedMb) * 1000000
		}
		admin := int64(2)
		if n.Up {
			admin = 1
		}
		l.add(e.Append(1, i), snmp.Integer(int64(n.Index)))
		l.add(e.Append(2, i), snmp.String(n.Name))
		l.add(e.Append(3, i), snmp.Integer(int64(n.Type)))
		l.add(e.Append(4, i), snmp.Integer32(n.MTU))
		l.add(e.Append(5, i), snmp.Gauge32(speed))
		l.add(e.Append(6, i), snmp.Bytes(n.MAC))
		l.add(e.Append(7, i), snmp.Integer(admin))
		l.add(e.Append(8, i), snmp.Integer(int64(n.Oper)))
		l.add(e.Append(9, i), snmp.TimeTicks(0))
		l.add(e.Append(10, i), c32(d.RxBytes))
		l.add(e.Append(11, i), c32(d.RxPackets-min(d.RxPackets, d.RxMulticast)))
		l.add(e.Append(13, i), c32(d.RxDrop))
		l.add(e.Append(14, i), c32(d.RxErrs))
		l.add(e.Append(15, i), c32(0))
		l.add(e.Append(16, i), c32(d.TxBytes))
		l.add(e.Append(17, i), c32(d.TxPackets))
		l.add(e.Append(19, i), c32(d.TxDrop))
		l.add(e.Append(20, i), c32(d.TxErrs))
	}
	return l
}

func (h *Host) ifXTable() []snmp.VarBind {
	ifs := h.FS.ReadNetIfs()
	dev := h.FS.ReadNetDev()
	var l vbs
	e := oidIfX.Append(1, 1, 1)
	for _, n := range ifs {
		i := uint32(n.Index)
		d := dev[n.Name]
		hs := uint64(0)
		if n.SpeedMb > 0 {
			hs = uint64(n.SpeedMb)
		}
		ucast := d.RxPackets - min(d.RxPackets, d.RxMulticast)
		l.add(e.Append(1, i), snmp.String(n.Name))
		l.add(e.Append(2, i), c32(d.RxMulticast))
		l.add(e.Append(3, i), c32(0))
		l.add(e.Append(4, i), c32(0))
		l.add(e.Append(5, i), c32(0))
		l.add(e.Append(6, i), snmp.Counter64(d.RxBytes))
		l.add(e.Append(7, i), snmp.Counter64(ucast))
		l.add(e.Append(8, i), snmp.Counter64(d.RxMulticast))
		l.add(e.Append(9, i), snmp.Counter64(0))
		l.add(e.Append(10, i), snmp.Counter64(d.TxBytes))
		l.add(e.Append(11, i), snmp.Counter64(d.TxPackets))
		l.add(e.Append(12, i), snmp.Counter64(0))
		l.add(e.Append(13, i), snmp.Counter64(0))
		l.add(e.Append(14, i), snmp.Integer(2))
		l.add(e.Append(15, i), snmp.Gauge32(hs))
		l.add(e.Append(16, i), snmp.Truth(false))
		l.add(e.Append(17, i), snmp.Truth(n.Ethernet))
		l.add(e.Append(18, i), snmp.String(""))
		l.add(e.Append(19, i), snmp.TimeTicks(0))
	}
	return l
}

func (h *Host) etherLike() []snmp.VarBind {
	var l vbs
	e := oidEther.Append(2, 1)
	for _, n := range h.FS.ReadNetIfs() {
		if !n.Ethernet {
			continue
		}
		i := uint32(n.Index)
		l.add(e.Append(1, i), snmp.Integer(int64(n.Index)))
		l.add(e.Append(19, i), snmp.Integer(int64(n.Duplex)))
	}
	return l
}

// dateAndTime is SNMPv2-TC's DateAndTime with the zone.
func dateAndTime(t time.Time) []byte {
	_, off := t.Zone()
	sign := byte('+')
	if off < 0 {
		sign, off = '-', -off
	}
	y := t.Year()
	return []byte{byte(y >> 8), byte(y), byte(t.Month()), byte(t.Day()), byte(t.Hour()), byte(t.Minute()), byte(t.Second()), byte(t.Nanosecond() / 100000000), sign, byte(off / 3600), byte(off % 3600 / 60)}
}

// DateAndTime exports dateAndTime for the Homematic tree.
func DateAndTime(t time.Time) []byte { return dateAndTime(t) }

// storage types (HOST-RESOURCES-TYPES)
var (
	hrStorageOther         = snmp.MustOID("1.3.6.1.2.1.25.2.1.1")
	hrStorageRAM           = snmp.MustOID("1.3.6.1.2.1.25.2.1.2")
	hrStorageVirtualMemory = snmp.MustOID("1.3.6.1.2.1.25.2.1.3")
	hrStorageFixedDisk     = snmp.MustOID("1.3.6.1.2.1.25.2.1.4")
	hrStorageRemovableDisk = snmp.MustOID("1.3.6.1.2.1.25.2.1.5")
	hrStorageNetworkDisk   = snmp.MustOID("1.3.6.1.2.1.25.2.1.10")
	hrDeviceProcessor      = snmp.MustOID("1.3.6.1.2.1.25.3.1.3")
	zeroDotZero            = snmp.MustOID("0.0")
)

type storage struct {
	index      uint32
	typ        snmp.OID
	descr      string
	unit, size uint64
	used       uint64
}

// fit scales units until size fits an Integer32, as net-snmp does.
func (s *storage) fit() {
	for s.size > 0x7fffffff {
		s.unit *= 2
		s.size /= 2
		s.used /= 2
	}
}

func (h *Host) storages() []storage {
	mi := h.FS.ReadMeminfo()
	total, free, buf, cached := mi["MemTotal"], mi["MemFree"], mi["Buffers"], mi["Cached"]
	shared := mi["Shmem"]
	st, sf := mi["SwapTotal"], mi["SwapFree"]
	out := []storage{
		{1, hrStorageRAM, "Physical memory", 1024, total, total - min(total, free)},
		{3, hrStorageVirtualMemory, "Virtual memory", 1024, total + st, total - min(total, free) + st - min(st, sf)},
		{6, hrStorageOther, "Memory buffers", 1024, total, buf},
		{7, hrStorageOther, "Cached memory", 1024, cached, cached},
		{8, hrStorageOther, "Shared memory", 1024, shared, shared},
		{10, hrStorageVirtualMemory, "Swap space", 1024, st, st - min(st, sf)},
	}
	for i, m := range h.FS.ReadMounts(h.Statfs) {
		typ := hrStorageFixedDisk
		switch {
		case m.Network:
			typ = hrStorageNetworkDisk
		case m.Removable:
			typ = hrStorageRemovableDisk
		}
		out = append(out, storage{uint32(31 + i), typ, m.Path, max(m.BlockSize, 1), m.Blocks, m.Blocks - min(m.Blocks, m.Free)})
	}
	for i := range out {
		out[i].fit()
	}
	return out
}

func (h *Host) hostResources() []snmp.VarBind {
	var l vbs
	r := oidHR
	now := h.Now()
	l.add(r.Append(1, 1, 0), snmp.TimeTicks(uint64(h.FS.ReadUptime()*100)))
	l.add(r.Append(1, 2, 0), snmp.Bytes(dateAndTime(now)))
	l.add(r.Append(1, 5, 0), snmp.Gauge32(0))
	l.add(r.Append(1, 6, 0), snmp.Gauge32(uint64(h.FS.Processes())))
	pidMax, _ := readInt(h.FS.proc("sys", "kernel", "pid_max"))
	l.add(r.Append(1, 7, 0), snmp.Integer32(pidMax))
	mi := h.FS.ReadMeminfo()
	l.add(r.Append(2, 2, 0), snmp.Integer32(int64(mi["MemTotal"])))
	for _, s := range h.storages() {
		e := r.Append(2, 3, 1)
		l.add(e.Append(1, s.index), snmp.Integer(int64(s.index)))
		l.add(e.Append(2, s.index), snmp.ObjectID(s.typ))
		l.add(e.Append(3, s.index), snmp.String(s.descr))
		l.add(e.Append(4, s.index), snmp.Integer32(int64(s.unit)))
		l.add(e.Append(5, s.index), snmp.Integer32(int64(s.size)))
		l.add(e.Append(6, s.index), snmp.Integer32(int64(s.used)))
		l.add(e.Append(7, s.index), snmp.Counter32(0))
	}
	ncpu := len(h.FS.ReadStat().CPUs)
	model := h.FS.CPUModel()
	if model == "" {
		model = "Processor"
	}
	loads := h.Sampler.ProcessorLoads(ncpu)
	for i := 0; i < ncpu; i++ {
		idx := uint32(196608 + i)
		e := r.Append(3, 2, 1)
		l.add(e.Append(1, idx), snmp.Integer(int64(idx)))
		l.add(e.Append(2, idx), snmp.ObjectID(hrDeviceProcessor))
		l.add(e.Append(3, idx), snmp.String(model))
		l.add(e.Append(4, idx), snmp.ObjectID(zeroDotZero))
		l.add(e.Append(5, idx), snmp.Integer(2))
		l.add(e.Append(6, idx), snmp.Counter32(0))
		p := r.Append(3, 3, 1)
		l.add(p.Append(1, idx), snmp.ObjectID(zeroDotZero))
		l.add(p.Append(2, idx), snmp.Integer(loads[i]))
	}
	return l
}

func kb(v uint64) snmp.Value { return snmp.Integer32(int64(v)) }

func (h *Host) ucd() []snmp.VarBind {
	var l vbs
	u := oidUCD
	mi := h.FS.ReadMeminfo()
	// memory (2021.4); memAvailReal is MemFree, as net-snmp has it
	m := u.Append(4)
	l.add(m.Append(1, 0), snmp.Integer(0))
	l.add(m.Append(2, 0), snmp.String("swap"))
	l.add(m.Append(3, 0), kb(mi["SwapTotal"]))
	l.add(m.Append(4, 0), kb(mi["SwapFree"]))
	l.add(m.Append(5, 0), kb(mi["MemTotal"]))
	l.add(m.Append(6, 0), kb(mi["MemFree"]))
	l.add(m.Append(11, 0), kb(mi["MemFree"]+mi["SwapFree"]))
	l.add(m.Append(12, 0), kb(16000))
	l.add(m.Append(13, 0), kb(mi["Shmem"]))
	l.add(m.Append(14, 0), kb(mi["Buffers"]))
	l.add(m.Append(15, 0), kb(mi["Cached"]))
	l.add(m.Append(100, 0), snmp.Integer(0))
	l.add(m.Append(101, 0), snmp.String(""))
	// dskTable (2021.9)
	for i, d := range h.FS.ReadMounts(h.Statfs) {
		idx := uint32(i + 1)
		e := u.Append(9, 1)
		bs := max(d.BlockSize, 1)
		totalK, availK := d.Blocks*bs/1024, d.Avail*bs/1024
		usedK := (d.Blocks - min(d.Blocks, d.Free)) * bs / 1024
		pctUsed, pctNode := int64(0), int64(0)
		if usedK+availK > 0 {
			pctUsed = int64((usedK*100 + usedK + availK - 1) / (usedK + availK))
		}
		if d.Files > 0 {
			pctNode = int64((d.Files - min(d.Files, d.FilesFree)) * 100 / d.Files)
		}
		l.add(e.Append(1, idx), snmp.Integer(int64(idx)))
		l.add(e.Append(2, idx), snmp.String(d.Path))
		l.add(e.Append(3, idx), snmp.String(d.Device))
		l.add(e.Append(4, idx), snmp.Integer(-1))
		l.add(e.Append(5, idx), snmp.Integer(-1))
		l.add(e.Append(6, idx), snmp.Integer32(int64(totalK)))
		l.add(e.Append(7, idx), snmp.Integer32(int64(availK)))
		l.add(e.Append(8, idx), snmp.Integer32(int64(usedK)))
		l.add(e.Append(9, idx), snmp.Integer(pctUsed))
		l.add(e.Append(10, idx), snmp.Integer(pctNode))
		l.add(e.Append(11, idx), snmp.Gauge32(totalK&0xffffffff))
		l.add(e.Append(12, idx), snmp.Gauge32(totalK>>32))
		l.add(e.Append(13, idx), snmp.Gauge32(availK&0xffffffff))
		l.add(e.Append(14, idx), snmp.Gauge32(availK>>32))
		l.add(e.Append(15, idx), snmp.Gauge32(usedK&0xffffffff))
		l.add(e.Append(16, idx), snmp.Gauge32(usedK>>32))
		l.add(e.Append(100, idx), snmp.Integer(0))
		l.add(e.Append(101, idx), snmp.String(""))
	}
	// laTable (2021.10)
	la := h.FS.ReadLoadavg()
	for i, name := range []string{"Load-1", "Load-5", "Load-15"} {
		idx := uint32(i + 1)
		e := u.Append(10, 1)
		l.add(e.Append(1, idx), snmp.Integer(int64(idx)))
		l.add(e.Append(2, idx), snmp.String(name))
		l.add(e.Append(3, idx), snmp.String(la[i]))
		l.add(e.Append(4, idx), snmp.String("12.00"))
		l.add(e.Append(5, idx), snmp.Integer(loadInt(la[i])))
		l.add(e.Append(100, idx), snmp.Integer(0))
		l.add(e.Append(101, idx), snmp.String(""))
	}
	// systemStats (2021.11)
	st := h.FS.ReadStat()
	vm := h.FS.ReadVmstat()
	cu, cs, ci := h.Sampler.CPUPercents()
	intr, ctxt, ioIn, ioOut, swIn, swOut := h.Sampler.Rates()
	s := u.Append(11)
	c := st.All
	l.add(s.Append(1, 0), snmp.Integer(1))
	l.add(s.Append(2, 0), snmp.String("systemStats"))
	l.add(s.Append(3, 0), snmp.Integer32(swIn))
	l.add(s.Append(4, 0), snmp.Integer32(swOut))
	l.add(s.Append(5, 0), snmp.Integer32(ioOut))
	l.add(s.Append(6, 0), snmp.Integer32(ioIn))
	l.add(s.Append(7, 0), snmp.Integer32(intr))
	l.add(s.Append(8, 0), snmp.Integer32(ctxt))
	l.add(s.Append(9, 0), snmp.Integer(cu))
	l.add(s.Append(10, 0), snmp.Integer(cs))
	l.add(s.Append(11, 0), snmp.Integer(ci))
	l.add(s.Append(50, 0), c32(c.User))
	l.add(s.Append(51, 0), c32(c.Nice))
	l.add(s.Append(52, 0), c32(c.System+c.IRQ+c.SoftIRQ))
	l.add(s.Append(53, 0), c32(c.Idle))
	l.add(s.Append(54, 0), c32(c.IOWait))
	l.add(s.Append(55, 0), c32(c.System))
	l.add(s.Append(56, 0), c32(c.IRQ))
	l.add(s.Append(57, 0), c32(vm["pgpgout"]))
	l.add(s.Append(58, 0), c32(vm["pgpgin"]))
	l.add(s.Append(59, 0), c32(st.Intr))
	l.add(s.Append(60, 0), c32(st.Ctxt))
	l.add(s.Append(61, 0), c32(c.SoftIRQ))
	l.add(s.Append(62, 0), c32(vm["pswpin"]))
	l.add(s.Append(63, 0), c32(vm["pswpout"]))
	l.add(s.Append(64, 0), c32(c.Steal))
	l.add(s.Append(65, 0), c32(c.Guest))
	l.add(s.Append(66, 0), c32(c.GuestNice))
	l.add(s.Append(67, 0), snmp.Integer(int64(len(st.CPUs))))
	// UCD-DISKIO-MIB diskIOTable (2021.13.15)
	for i, d := range h.FS.ReadDiskstats() {
		idx := uint32(i + 1)
		e := u.Append(13, 15, 1, 1)
		lav := h.Sampler.DiskLA(d.Name)
		rb, wb := d.SectorsRead*512, d.SectorsWritten*512
		l.add(e.Append(1, idx), snmp.Integer(int64(idx)))
		l.add(e.Append(2, idx), snmp.String(d.Name))
		l.add(e.Append(3, idx), c32(rb))
		l.add(e.Append(4, idx), c32(wb))
		l.add(e.Append(5, idx), c32(d.Reads))
		l.add(e.Append(6, idx), c32(d.Writes))
		l.add(e.Append(9, idx), snmp.Integer(lav[0]))
		l.add(e.Append(10, idx), snmp.Integer(lav[1]))
		l.add(e.Append(11, idx), snmp.Integer(lav[2]))
		l.add(e.Append(12, idx), snmp.Counter64(rb))
		l.add(e.Append(13, idx), snmp.Counter64(wb))
		l.add(e.Append(14, idx), snmp.Counter64(d.IOMillis*1000))
	}
	// LM-SENSORS-MIB lmTempSensorsTable (2021.13.16.2)
	for _, t := range h.FS.ReadThermal() {
		idx := uint32(t.Index)
		e := u.Append(13, 16, 2, 1)
		l.add(e.Append(1, idx), snmp.Integer(int64(idx)))
		l.add(e.Append(2, idx), snmp.String(t.Name))
		l.add(e.Append(3, idx), snmp.Gauge32(uint64(max(t.MilliC, 0))))
	}
	return l
}

func loadInt(s string) int64 {
	whole, frac, _ := strings.Cut(s, ".")
	var v int64
	for _, c := range whole {
		if c >= '0' && c <= '9' {
			v = v*10 + int64(c-'0')
		}
	}
	v *= 100
	f := (frac + "00")[:2]
	for i, c := range f {
		if c >= '0' && c <= '9' {
			if i == 0 {
				v += int64(c-'0') * 10
			} else {
				v += int64(c - '0')
			}
		}
	}
	return v
}
