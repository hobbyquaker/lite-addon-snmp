// Package hostmib answers the standard MIB subset network management systems poll for a Linux
// host - the system group, IF-MIB, EtherLike-MIB's duplex, HOST-RESOURCES-MIB and UCD-SNMP-MIB
// with UCD-DISKIO-MIB and the temperature sensors - computed in pure Go from /proc, /sys and
// statfs. The shapes follow net-snmp's Linux agent, which the NMSs' templates were written
// against: the same storage indices and descriptions, the same CPU counters.
package hostmib

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// FS names the roots the package reads; the tests point them at fixtures.
type FS struct {
	Proc string // /proc
	Sys  string // /sys
}

// DefaultFS is the running system.
var DefaultFS = FS{Proc: "/proc", Sys: "/sys"}

func (f FS) proc(p ...string) string { return filepath.Join(append([]string{f.Proc}, p...)...) }
func (f FS) sys(p ...string) string  { return filepath.Join(append([]string{f.Sys}, p...)...) }

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func readInt(p string) (int64, bool) {
	v, err := strconv.ParseInt(readTrim(p), 10, 64)
	return v, err == nil
}

// Meminfo is /proc/meminfo in kB.
type Meminfo map[string]uint64

// ReadMeminfo reads /proc/meminfo.
func (f FS) ReadMeminfo() Meminfo {
	m := Meminfo{}
	b, err := os.ReadFile(f.proc("meminfo"))
	if err != nil {
		return m
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		n, err := strconv.ParseUint(fs[0], 10, 64)
		if err == nil {
			m[k] = n
		}
	}
	return m
}

// CPUTimes are one line of /proc/stat in USER_HZ ticks.
type CPUTimes struct {
	User, Nice, System, Idle, IOWait, IRQ, SoftIRQ, Steal, Guest, GuestNice uint64
}

// Total is every tick (guest time is already in user).
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.IOWait + c.IRQ + c.SoftIRQ + c.Steal
}

// Busy is everything but idle and iowait.
func (c CPUTimes) Busy() uint64 { return c.Total() - c.Idle - c.IOWait }

// Stat is /proc/stat.
type Stat struct {
	All       CPUTimes
	CPUs      []CPUTimes
	Intr      uint64
	Ctxt      uint64
	BootTime  int64
	Processes uint64
}

// ReadStat reads /proc/stat.
func (f FS) ReadStat() Stat {
	var s Stat
	b, err := os.ReadFile(f.proc("stat"))
	if err != nil {
		return s
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) < 2 {
			continue
		}
		switch {
		case fs[0] == "cpu":
			s.All = parseCPU(fs[1:])
		case strings.HasPrefix(fs[0], "cpu"):
			s.CPUs = append(s.CPUs, parseCPU(fs[1:]))
		case fs[0] == "intr":
			s.Intr, _ = strconv.ParseUint(fs[1], 10, 64)
		case fs[0] == "ctxt":
			s.Ctxt, _ = strconv.ParseUint(fs[1], 10, 64)
		case fs[0] == "btime":
			s.BootTime, _ = strconv.ParseInt(fs[1], 10, 64)
		case fs[0] == "processes":
			s.Processes, _ = strconv.ParseUint(fs[1], 10, 64)
		}
	}
	return s
}

func parseCPU(fs []string) CPUTimes {
	v := make([]uint64, 10)
	for i := 0; i < len(fs) && i < 10; i++ {
		v[i], _ = strconv.ParseUint(fs[i], 10, 64)
	}
	return CPUTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]}
}

// Vmstat is /proc/vmstat.
func (f FS) ReadVmstat() map[string]uint64 {
	out := map[string]uint64{}
	b, err := os.ReadFile(f.proc("vmstat"))
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, " ")
		if !ok {
			continue
		}
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			out[k] = n
		}
	}
	return out
}

// Loadavg is /proc/loadavg's three averages, as printed.
func (f FS) ReadLoadavg() [3]string {
	fs := strings.Fields(readTrim(f.proc("loadavg")))
	var out [3]string
	for i := range out {
		out[i] = "0.00"
		if i < len(fs) {
			out[i] = fs[i]
		}
	}
	return out
}

// Uptime is the host's uptime in seconds.
func (f FS) ReadUptime() float64 {
	fs := strings.Fields(readTrim(f.proc("uptime")))
	if len(fs) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(fs[0], 64)
	return v
}

// NetDev is one line of /proc/net/dev.
type NetDev struct {
	Name                                            string
	RxBytes, RxPackets, RxErrs, RxDrop, RxMulticast uint64
	TxBytes, TxPackets, TxErrs, TxDrop              uint64
}

// ReadNetDev reads /proc/net/dev.
func (f FS) ReadNetDev() map[string]NetDev {
	out := map[string]NetDev{}
	b, err := os.ReadFile(f.proc("net", "dev"))
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		name, rest, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		fs := strings.Fields(rest)
		if len(fs) < 16 {
			continue
		}
		v := make([]uint64, 16)
		for i := range v {
			v[i], _ = strconv.ParseUint(fs[i], 10, 64)
		}
		n := strings.TrimSpace(name)
		out[n] = NetDev{Name: n, RxBytes: v[0], RxPackets: v[1], RxErrs: v[2], RxDrop: v[3], RxMulticast: v[7],
			TxBytes: v[8], TxPackets: v[9], TxErrs: v[10], TxDrop: v[11]}
	}
	return out
}

// DiskStat is one line of /proc/diskstats.
type DiskStat struct {
	Name                   string
	Reads, SectorsRead     uint64
	Writes, SectorsWritten uint64
	IOMillis               uint64
	Major, Minor           uint64
}

// ReadDiskstats reads /proc/diskstats: the block devices a disk I/O table lists (SD cards, SATA
// and USB disks, NVMe, virtio), whole disks and partitions, never loop, ram or zram devices.
func (f FS) ReadDiskstats() []DiskStat {
	var out []DiskStat
	b, err := os.ReadFile(f.proc("diskstats"))
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		fs := strings.Fields(l)
		if len(fs) < 14 {
			continue
		}
		name := fs[2]
		if !diskName(name) {
			continue
		}
		v := make([]uint64, len(fs))
		for i := range fs {
			v[i], _ = strconv.ParseUint(fs[i], 10, 64)
		}
		out = append(out, DiskStat{Name: name, Major: v[0], Minor: v[1], Reads: v[3], SectorsRead: v[5], Writes: v[7], SectorsWritten: v[9], IOMillis: v[12]})
	}
	return out
}

func diskName(n string) bool {
	for _, p := range []string{"mmcblk", "sd", "nvme", "vd", "xvd", "hd", "dm-", "md"} {
		if strings.HasPrefix(n, p) {
			return !strings.Contains(n, "boot") && !strings.Contains(n, "rpmb")
		}
	}
	return false
}

// CPUModel is the processor's description from /proc/cpuinfo.
func (f FS) CPUModel() string {
	b, err := os.ReadFile(f.proc("cpuinfo"))
	if err != nil {
		return ""
	}
	var model, hw string
	for _, l := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "model name":
			if model == "" {
				model = v
			}
		case "Model":
			if hw == "" {
				hw = v
			}
		}
	}
	if model == "" {
		model = hw
	}
	return model
}

// Processes counts the numeric entries of /proc.
func (f FS) Processes() int {
	ents, err := os.ReadDir(f.Proc)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() && e.Name()[0] >= '0' && e.Name()[0] <= '9' {
			n++
		}
	}
	return n
}
