package hostmib

import (
	"context"
	"math"
	"sync"
	"time"
)

// SampleEvery is the sampler's period.
const SampleEvery = 5 * time.Second

type sample struct {
	at   time.Time
	stat Stat
	vm   map[string]uint64
}

// Sampler keeps a minute of /proc/stat and /proc/vmstat samples for the averages the MIBs carry
// (hrProcessorLoad, ssCpuUser, ssSysInterrupts, …) and the disks' load averages.
type Sampler struct {
	fs   FS
	mu   sync.Mutex
	ring []sample
	// disk busy fractions, exponentially averaged over 1, 5 and 15 minutes
	diskLA   map[string]*[3]float64
	lastDisk map[string]DiskStat
	lastAt   time.Time
}

// NewSampler makes a sampler; Run fills it.
func NewSampler(fs FS) *Sampler {
	s := &Sampler{fs: fs, diskLA: map[string]*[3]float64{}, lastDisk: map[string]DiskStat{}}
	s.Sample(time.Now())
	return s
}

// Run samples every SampleEvery until ctx ends.
func (s *Sampler) Run(ctx context.Context) {
	t := time.NewTicker(SampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.Sample(now)
		}
	}
}

// Sample takes one sample.
func (s *Sampler) Sample(now time.Time) {
	st := s.fs.ReadStat()
	vm := s.fs.ReadVmstat()
	disks := s.fs.ReadDiskstats()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ring = append(s.ring, sample{at: now, stat: st, vm: vm})
	for len(s.ring) > 2 && now.Sub(s.ring[0].at) > time.Minute+SampleEvery/2 {
		s.ring = s.ring[1:]
	}
	if !s.lastAt.IsZero() {
		dt := now.Sub(s.lastAt).Seconds()
		if dt > 0 {
			for _, d := range disks {
				prev, ok := s.lastDisk[d.Name]
				if !ok || d.IOMillis < prev.IOMillis {
					continue
				}
				busy := math.Min(1, float64(d.IOMillis-prev.IOMillis)/1000/dt)
				la := s.diskLA[d.Name]
				if la == nil {
					la = &[3]float64{busy, busy, busy}
					s.diskLA[d.Name] = la
				}
				for i, win := range []float64{60, 300, 900} {
					a := math.Exp(-dt / win)
					la[i] = la[i]*a + busy*(1-a)
				}
			}
		}
	}
	s.lastAt = now
	s.lastDisk = map[string]DiskStat{}
	for _, d := range disks {
		s.lastDisk[d.Name] = d
	}
}

// window answers the oldest and newest sample of the last minute.
func (s *Sampler) window() (first, last sample, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.ring) < 2 {
		return sample{}, sample{}, false
	}
	return s.ring[0], s.ring[len(s.ring)-1], true
}

// ProcessorLoads is each CPU's busy percentage over the last minute.
func (s *Sampler) ProcessorLoads(n int) []int64 {
	out := make([]int64, n)
	a, b, ok := s.window()
	if !ok {
		return out
	}
	for i := 0; i < n && i < len(a.stat.CPUs) && i < len(b.stat.CPUs); i++ {
		out[i] = pct(b.stat.CPUs[i].Busy()-a.stat.CPUs[i].Busy(), b.stat.CPUs[i].Total()-a.stat.CPUs[i].Total())
	}
	return out
}

func pct(part, total uint64) int64 {
	if total == 0 || part > total {
		return 0
	}
	return int64(math.Round(float64(part) * 100 / float64(total)))
}

// CPUPercents are ssCpuUser, ssCpuSystem and ssCpuIdle over the last minute.
func (s *Sampler) CPUPercents() (user, system, idle int64) {
	a, b, ok := s.window()
	if !ok {
		return 0, 0, 100
	}
	x, y := a.stat.All, b.stat.All
	t := y.Total() - x.Total()
	if t == 0 || y.Total() < x.Total() {
		return 0, 0, 100
	}
	return pct((y.User+y.Nice)-(x.User+x.Nice), t), pct((y.System+y.IRQ+y.SoftIRQ)-(x.System+x.IRQ+x.SoftIRQ), t), pct(y.Idle-x.Idle, t)
}

// Rates are the per-second averages of the last minute: interrupts, context switches, the I/O
// blocks in and out (kB, from pgpgin/pgpgout) and the swapping (kB).
func (s *Sampler) Rates() (intr, ctxt, ioIn, ioOut, swapIn, swapOut int64) {
	a, b, ok := s.window()
	if !ok {
		return
	}
	dt := b.at.Sub(a.at).Seconds()
	if dt <= 0 {
		return
	}
	rate := func(x, y uint64) int64 {
		if y < x {
			return 0
		}
		return int64(math.Round(float64(y-x) / dt))
	}
	return rate(a.stat.Intr, b.stat.Intr), rate(a.stat.Ctxt, b.stat.Ctxt), rate(a.vm["pgpgin"], b.vm["pgpgin"]), rate(a.vm["pgpgout"], b.vm["pgpgout"]),
		rate(a.vm["pswpin"], b.vm["pswpin"]) * 4, rate(a.vm["pswpout"], b.vm["pswpout"]) * 4
}

// DiskLA answers a disk's 1, 5 and 15 minute busy percentages.
func (s *Sampler) DiskLA(name string) [3]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	la := s.diskLA[name]
	if la == nil {
		return [3]int64{}
	}
	return [3]int64{int64(math.Round(la[0] * 100)), int64(math.Round(la[1] * 100)), int64(math.Round(la[2] * 100))}
}
