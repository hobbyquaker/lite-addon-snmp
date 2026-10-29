package hostmib

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// NetIf is one network interface from /sys/class/net.
type NetIf struct {
	Name     string
	Index    int
	Type     int   // ifType (IANAifType)
	Up       bool  // administratively (IFF_UP)
	Oper     int   // ifOperStatus
	SpeedMb  int64 // -1 unknown
	Duplex   int   // EtherLike: unknown(1) half(2) full(3)
	MTU      int64
	MAC      []byte
	Ethernet bool
}

// ReadNetIfs lists the interfaces by ifindex.
func (f FS) ReadNetIfs() []NetIf {
	ents, err := os.ReadDir(f.sys("class", "net"))
	if err != nil {
		return nil
	}
	var out []NetIf
	for _, e := range ents {
		name := e.Name()
		if strings.HasPrefix(name, ".") || name == "bonding_masters" {
			continue
		}
		d := f.sys("class", "net", name)
		idx, ok := readInt(filepath.Join(d, "ifindex"))
		if !ok {
			continue
		}
		n := NetIf{Name: name, Index: int(idx), SpeedMb: -1, Duplex: 1}
		arp, _ := readInt(filepath.Join(d, "type"))
		_, werr := os.Stat(filepath.Join(d, "wireless"))
		switch {
		case arp == 772:
			n.Type = 24 // softwareLoopback
		case werr == nil:
			n.Type, n.Ethernet = 71, false // ieee80211
		case arp == 1:
			n.Type, n.Ethernet = 6, true // ethernetCsmacd
		case arp == 65534 || arp == 768 || arp == 776 || arp == 778:
			n.Type = 131 // tunnel
		default:
			n.Type = 1
		}
		if fl := readTrim(filepath.Join(d, "flags")); fl != "" {
			if v, err := strconv.ParseInt(strings.TrimPrefix(fl, "0x"), 16, 64); err == nil {
				n.Up = v&1 != 0
			}
		}
		switch readTrim(filepath.Join(d, "operstate")) {
		case "up":
			n.Oper = 1
		case "down":
			n.Oper = 2
		case "testing":
			n.Oper = 3
		case "dormant":
			n.Oper = 5
		case "notpresent":
			n.Oper = 6
		case "lowerlayerdown":
			n.Oper = 7
		default:
			// loopback and tunnels say "unknown" while they carry traffic
			if n.Up && (n.Type == 24 || n.Type == 131) {
				n.Oper = 1
			} else {
				n.Oper = 4
			}
		}
		if s, ok := readInt(filepath.Join(d, "speed")); ok && s > 0 {
			n.SpeedMb = s
		}
		switch readTrim(filepath.Join(d, "duplex")) {
		case "full":
			n.Duplex = 3
		case "half":
			n.Duplex = 2
		}
		n.MTU, _ = readInt(filepath.Join(d, "mtu"))
		if mac := readTrim(filepath.Join(d, "address")); mac != "" && n.Type != 24 {
			for _, p := range strings.Split(mac, ":") {
				if v, err := strconv.ParseUint(p, 16, 8); err == nil {
					n.MAC = append(n.MAC, byte(v))
				}
			}
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Thermal is one thermal zone.
type Thermal struct {
	Index  int
	Name   string
	MilliC int64
}

// ReadThermal lists /sys/class/thermal/thermal_zone*.
func (f FS) ReadThermal() []Thermal {
	m, _ := filepath.Glob(f.sys("class", "thermal", "thermal_zone*"))
	var out []Thermal
	for _, d := range m {
		n, err := strconv.Atoi(strings.TrimPrefix(filepath.Base(d), "thermal_zone"))
		if err != nil {
			continue
		}
		t, ok := readInt(filepath.Join(d, "temp"))
		if !ok {
			continue
		}
		name := readTrim(filepath.Join(d, "type"))
		if name == "" {
			name = filepath.Base(d)
		}
		out = append(out, Thermal{Index: n + 1, Name: name, MilliC: t})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out
}

// Mount is one mounted filesystem with its sizes.
type Mount struct {
	Path, Device, FSType string
	Dev                  string // major:minor
	BlockSize            uint64
	Blocks, Free, Avail  uint64
	Files, FilesFree     uint64
	Network, Removable   bool
}

var realFS = map[string]bool{"ext2": true, "ext3": true, "ext4": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true, "fuseblk": true, "f2fs": true, "btrfs": true, "xfs": true, "hfsplus": true, "squashfs": false, "nfs": true, "nfs4": true, "cifs": true, "smb3": true}

// ReadMounts lists the real filesystems from /proc/self/mountinfo: each filesystem once (its
// first mount of the filesystem's root; the sandbox's bind mounts of subdirectories are left
// out), with statfs's numbers.
func (f FS) ReadMounts(statfs func(string, *syscall.Statfs_t) error) []Mount {
	b, err := os.ReadFile(f.proc("self", "mountinfo"))
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	seenPath := map[string]bool{}
	var out []Mount
	for _, l := range strings.Split(string(b), "\n") {
		pre, post, ok := strings.Cut(l, " - ")
		if !ok {
			continue
		}
		a, c := strings.Fields(pre), strings.Fields(post)
		if len(a) < 5 || len(c) < 2 {
			continue
		}
		fstype, src := c[0], c[1]
		if !realFS[fstype] {
			continue
		}
		root, mp, dev := a[3], unescape(a[4]), a[2]
		if root != "/" || seen[dev] || seenPath[mp] {
			continue
		}
		seen[dev], seenPath[mp] = true, true
		m := Mount{Path: mp, Device: src, FSType: fstype, Dev: dev}
		switch fstype {
		case "nfs", "nfs4", "cifs", "smb3":
			m.Network = true
		}
		m.Removable = strings.HasPrefix(mp, "/media/")
		var st syscall.Statfs_t
		if statfs != nil && statfs(mp, &st) == nil {
			bs := uint64(st.Frsize)
			if bs == 0 {
				bs = uint64(st.Bsize)
			}
			m.BlockSize, m.Blocks, m.Free, m.Avail = bs, st.Blocks, st.Bfree, st.Bavail
			m.Files, m.FilesFree = st.Files, st.Ffree
		}
		out = append(out, m)
	}
	return out
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
