package source

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/hobbyquaker/ccu-addon-kit/go/addonkit"
)

// SysClient reads occulited's system API (/api/system/v1) with the addon's token (system:read).
type SysClient struct {
	Base string
	HTTP *http.Client
}

// NewSysClient makes a client of base with the token source.
func NewSysClient(base string, token addonkit.TokenSource) *SysClient {
	if base == "" {
		base = "http://127.0.0.1"
	}
	return &SysClient{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Transport: &addonkit.AuthTransport{Source: token}}}
}

// Get decodes one JSON answer.
func (c *SysClient) Get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return err
	}
	if res.StatusCode/100 != 2 {
		return fmt.Errorf("%s: http %d: %.200s", path, res.StatusCode, b)
	}
	return json.Unmarshal(b, out)
}

// Stream opens an SSE route and calls emit for every message until the stream ends.
func (c *SysClient) Stream(ctx context.Context, path string, emit func(event, data string)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: http %d", path, res.StatusCode)
	}
	// a stream that says nothing for 90 s (occulited pings every 30 s) is dead
	alive := make(chan struct{}, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		t := time.NewTimer(90 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-alive:
				t.Reset(90 * time.Second)
			case <-t.C:
				res.Body.Close()
				return
			}
		}
	}()
	sc := bufio.NewScanner(res.Body)
	sc.Buffer(make([]byte, 64<<10), 16<<20)
	var event string
	var data []string
	for sc.Scan() {
		select {
		case alive <- struct{}{}:
		default:
		}
		line := strings.TrimRight(sc.Text(), "\r")
		if line == "" {
			if len(data) > 0 {
				if event == "" {
					event = "message"
				}
				emit(event, strings.Join(data, "\n"))
			}
			event, data = "", nil
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		f, v, _ := strings.Cut(line, ":")
		v = strings.TrimPrefix(v, " ")
		switch f {
		case "event":
			event = v
		case "data":
			data = append(data, v)
		}
	}
	if err := sc.Err(); err != nil {
		return err
	}
	return io.EOF
}

// The system API's answers, the fields the agent reads.

// Health is GET /api/system/v1/health.
type Health struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Release string `json:"release"`
	Base    string `json:"base"`
	Meta    struct {
		Revision int64 `json:"revision"`
	} `json:"meta"`
}

// RadioEntry is one entry of GET /radio/health's interfaces.
type RadioEntry struct {
	Interface    string `json:"interface"`
	Address      string `json:"address"`
	Type         string `json:"type"`
	Connected    bool   `json:"connected"`
	Default      bool   `json:"default"`
	Firmware     string `json:"firmware"`
	DutyCycle    int    `json:"duty_cycle"`
	CarrierSense *int   `json:"carrier_sense"`
	RadioName    string `json:"radio_name"`
	Module       string `json:"module"`
	DCThreshold  int    `json:"dc_threshold"`
}

// RadioUnit is one radio stack unit of GET /radio/health.
type RadioUnit struct {
	Unit        string   `json:"unit"`
	Interfaces  []string `json:"interfaces"`
	ActiveState string   `json:"active_state"`
	SubState    string   `json:"sub_state"`
}

// RadioHealth is GET /api/system/v1/radio/health.
type RadioHealth struct {
	Interfaces  []RadioEntry                   `json:"interfaces"`
	Units       []RadioUnit                    `json:"units"`
	Subscribers map[string]struct{ Total int } `json:"subscribers"`
	Busy        bool                           `json:"busy"`
}

// ServiceMessage is one message of GET /service-messages.
type ServiceMessage struct {
	Interface string          `json:"interface"`
	Address   string          `json:"address"`
	Channel   json.RawMessage `json:"channel"`
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	Since     time.Time       `json:"since"`
	Seen      string          `json:"seen"`
	Type      string          `json:"type"`
	Name      string          `json:"name"`
	Enums     []string        `json:"enums"`
	EnumNames []string        `json:"enum_names"`
}

// ChannelAddress is the message's channel address (<device>:<channel>).
func (m ServiceMessage) ChannelAddress() string {
	ch := strings.Trim(string(m.Channel), `"`)
	if ch == "" || ch == "null" {
		ch = "0"
	}
	if strings.Contains(m.Address, ":") {
		return m.Address
	}
	return m.Address + ":" + ch
}

// ID is the message's identity: interface, address and key.
func (m ServiceMessage) ID() string { return m.Interface + "/" + m.Address + "/" + m.Key }

// ServiceMessages is GET /service-messages.
type ServiceMessages struct {
	Count    int              `json:"count"`
	Messages []ServiceMessage `json:"messages"`
}

// Warning is one Status page warning.
type Warning struct {
	ID       string          `json:"id"`
	Variant  string          `json:"variant"`
	Severity string          `json:"severity"`
	Params   json.RawMessage `json:"params,omitempty"`
}

// Key is the warning's identity.
func (w Warning) Key() string { return w.ID + "/" + w.Variant }

// Warnings is GET /warnings.
type Warnings struct {
	Warnings []Warning `json:"warnings"`
}

// Stalls is GET /radio/subscribers/stalls.
type Stalls struct {
	Stalls []json.RawMessage `json:"stalls"`
}
