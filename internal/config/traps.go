package config

import (
	"fmt"
	"net"
	"strings"
)

// The notification rules' kinds.
const (
	RuleServiceMessage = "service-message"
	RuleInterface      = "interface"
	RuleDutyCycle      = "duty-cycle"
	RuleService        = "service"
	RuleWarning        = "warning"
	RuleUnreachable    = "unreachable"
)

// RuleKinds lists the kinds in the order the UI shows them.
var RuleKinds = []string{RuleServiceMessage, RuleInterface, RuleDutyCycle, RuleService, RuleWarning, RuleUnreachable}

// The targets' kinds.
const (
	TargetV2cTrap  = "v2c-trap"
	TargetV3Trap   = "v3-trap"
	TargetV3Inform = "v3-inform"
)

// Rule is one notification rule: a kind, switched on or off, with the selection of objects it
// watches (for the kinds about devices) and the duty cycle threshold.
type Rule struct {
	Kind    string `json:"kind"`
	Enabled bool   `json:"enabled"`
	// Selection is a selection id; "" watches every device.
	Selection string `json:"selection"`
	// Threshold is the duty cycle in percent from which hmDutyCycleHigh is raised; 0 takes the
	// interface's own threshold, else 80.
	Threshold int `json:"threshold,omitempty"`
}

// Target is one receiver.
type Target struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Kind    string `json:"kind"`
	// Community is the v2c trap's community.
	Community string `json:"community,omitempty"`
	// User is the agent's SNMPv3 user the v3 trap or inform is sent as.
	User string `json:"user,omitempty"`
	// Rules are the rule kinds the target gets; empty: every enabled rule.
	Rules []string `json:"rules"`
}

// Traps are the targets and the rules.
type Traps struct {
	Targets []Target `json:"targets"`
	Rules   []Rule   `json:"rules"`
}

// DefaultTraps are the rules of a fresh install (no target, so nothing is sent).
func DefaultTraps() Traps {
	t := Traps{Targets: []Target{}}
	for _, k := range RuleKinds {
		t.Rules = append(t.Rules, Rule{Kind: k, Enabled: k != RuleUnreachable})
	}
	return t
}

func (t *Traps) normalise() {
	if t.Targets == nil {
		t.Targets = []Target{}
	}
	have := map[string]bool{}
	for _, r := range t.Rules {
		have[r.Kind] = true
	}
	for _, k := range RuleKinds {
		if !have[k] {
			t.Rules = append(t.Rules, Rule{Kind: k, Enabled: k != RuleUnreachable})
		}
	}
	for i := range t.Targets {
		if t.Targets[i].Rules == nil {
			t.Targets[i].Rules = []string{}
		}
		if t.Targets[i].Port == 0 {
			t.Targets[i].Port = 162
		}
	}
}

// Rule answers the rule of a kind.
func (t Traps) Rule(kind string) Rule {
	for _, r := range t.Rules {
		if r.Kind == kind {
			return r
		}
	}
	return Rule{Kind: kind}
}

func (t *Traps) validate(selections, credentials map[string]bool) error {
	kinds := map[string]bool{}
	for _, k := range RuleKinds {
		kinds[k] = true
	}
	for _, r := range t.Rules {
		if !kinds[r.Kind] {
			return fmt.Errorf("unknown rule %q", r.Kind)
		}
		if r.Selection != "" && !selections[r.Selection] {
			return fmt.Errorf("rule %s: the selection does not exist", r.Kind)
		}
		if r.Threshold < 0 || r.Threshold > 100 {
			return fmt.Errorf("rule %s: the threshold is a percentage", r.Kind)
		}
	}
	ids := map[string]bool{}
	for _, tg := range t.Targets {
		if tg.ID == "" || ids[tg.ID] {
			return fmt.Errorf("target %q: missing or duplicate id", tg.Name)
		}
		ids[tg.ID] = true
		if strings.TrimSpace(tg.Name) == "" || len(tg.Name) > 64 {
			return fmt.Errorf("a target needs a name")
		}
		h := strings.TrimSpace(tg.Host)
		if h == "" || len(h) > 253 || strings.ContainsAny(h, " /:\\") && net.ParseIP(h) == nil {
			return fmt.Errorf("target %q: the host is a name or an address", tg.Name)
		}
		if tg.Port < 1 || tg.Port > 65535 {
			return fmt.Errorf("target %q: the port is 1 to 65535", tg.Name)
		}
		switch tg.Kind {
		case TargetV2cTrap:
			if tg.Community == "" || len(tg.Community) > 64 {
				return fmt.Errorf("target %q: a v2c trap needs a community", tg.Name)
			}
		case TargetV3Trap, TargetV3Inform:
			if !credentials["u:"+tg.User] {
				return fmt.Errorf("target %q: the user does not exist", tg.Name)
			}
		default:
			return fmt.Errorf("target %q: unknown kind %q", tg.Name, tg.Kind)
		}
		for _, k := range tg.Rules {
			if !kinds[k] {
				return fmt.Errorf("target %q: unknown rule %q", tg.Name, k)
			}
		}
	}
	return nil
}
