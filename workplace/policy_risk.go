package workplace

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Risk is a policy's effective risk level (docs/design/v2/policy.md §6).
type Risk int

const (
	RiskLow Risk = iota + 1
	RiskMedium
	RiskHigh
	RiskCritical
)

var riskNames = map[Risk]string{RiskLow: "LOW", RiskMedium: "MEDIUM", RiskHigh: "HIGH", RiskCritical: "CRITICAL"}

func (r Risk) String() string {
	if s, ok := riskNames[r]; ok {
		return s
	}
	return "Risk(" + strconv.Itoa(int(r)) + ")"
}

func (r Risk) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

// ParseRisk parses LOW, MEDIUM, HIGH or CRITICAL.
func ParseRisk(s string) (Risk, error) {
	for r, n := range riskNames {
		if n == s {
			return r, nil
		}
	}
	return 0, fmt.Errorf("workplace: unknown risk level %q (LOW, MEDIUM, HIGH, CRITICAL)", s)
}

// RiskReport is the effective risk of a policy.
type RiskReport struct {
	Level    Risk     `json:"level"`
	Reasons  []string `json:"reasons"`
	Warnings []string `json:"warnings"`
	PolicyID string   `json:"policy_id"`
}

// Canary names: a mask that matches one of them is treated as matching everything.
var (
	moduleCanaries = []string{"canary-1.invalid/x", "canary-2.invalid", "x.canary-3.invalid/a/b/c", "Canary-4.invalid/X/v2"}
	hostCanaries   = []string{"canary-1.invalid", "canary-2.invalid", "x.canary-3.invalid", "192.0.2.1", "2001:db8::1"}
	broadHosts     = []string{"github.com", "googleapis.com", "githubusercontent.com", "amazonaws.com", "huggingface.co"}
)

func firstCanary(mask string, canaries []string) (string, bool) {
	for _, c := range canaries {
		if maskMatches(mask, c) {
			return c, true
		}
	}
	return "", false
}

// unescapedDot reports a '.' outside a character class that is not escaped.
func unescapedDot(mask string) bool {
	esc, class := false, false
	for _, c := range mask {
		switch {
		case esc:
			esc = false
		case c == '\\':
			esc = true
		case c == '[':
			class = true
		case c == ']':
			class = false
		case c == '.' && !class:
			return true
		}
	}
	return false
}

var escapedDotRE = regexp.MustCompile(`\\\.`)

// broadHost returns the broad domain a host mask admits, by matching the domain or a subdomain of it,
// or by naming it in the mask's text.
func broadHost(mask string) (string, bool) {
	text := strings.ToLower(escapedDotRE.ReplaceAllString(mask, "."))
	for _, d := range broadHosts {
		if maskMatches(mask, d) || maskMatches(mask, "rwp-probe."+d) || strings.Contains(text, d) {
			return d, true
		}
	}
	return "", false
}

// EffectiveRisk returns the level (the §6 table cell raised by the modifiers), the reasons, the warnings and the policy id.
// yolo counts as exec with no rules and never lowers a level; read-only never lowers a networked level.
func EffectiveRisk(p Policy) RiskReport {
	r := RiskReport{PolicyID: p.ID(), Reasons: []string{}, Warnings: []string{}}
	raise := func(l Risk, reason string) {
		r.Level = max(r.Level, l)
		r.Reasons = append(r.Reasons, reason+" ("+l.String()+")")
	}
	rwExec := p.Workspace.Access == "read-write" && p.Exec()
	n := p.Network
	switch n.Mode {
	case NetNone:
		if rwExec {
			raise(RiskMedium, "none: no egress; read-write workspace with an exec tool can plant code in the patch")
		} else {
			raise(RiskLow, "none: no egress; read-only workspace or no exec tool")
		}
	case NetModules:
		raise(RiskMedium, "modules: covert channel via module paths, bounded by masks, rate and log")
		for _, m := range n.GoModules {
			if c, ok := firstCanary(m, moduleCanaries); ok {
				raise(RiskHigh, fmt.Sprintf("modules: mask %q matches canary %q: any host receives lookups", m, c))
			}
		}
	case NetAllowlist:
		raise(RiskHigh, "allowlist: exfiltration to or through allowed hosts and fronting are not contained")
		for _, h := range n.Hosts {
			if c, ok := firstCanary(h, hostCanaries); ok {
				raise(RiskCritical, fmt.Sprintf("allowlist: host mask %q matches canary %q: an allowlist that is all", h, c))
			}
			if d, ok := broadHost(h); ok {
				r.Warnings = append(r.Warnings, fmt.Sprintf("host mask %q admits broad host %s (attacker-writable storage)", h, d))
			}
		}
	case NetDenylist:
		raise(RiskCritical, "denylist: effectively all; alternate names and IP literals bypass a name denylist")
	case NetAll:
		raise(RiskCritical, "all: everything the worker can read can leave")
	default:
		raise(RiskCritical, fmt.Sprintf("unknown network mode %q", n.Mode))
	}
	if n.Mode != NetNone && p.Workspace.Access == "read-only" {
		r.Reasons = append(r.Reasons, "read-only workspace does not lower the level: reads can leave")
	}
	if p.Tools.Mode == "yolo" {
		r.Reasons = append(r.Reasons, "yolo: no tool rules")
	}
	for _, h := range n.Hosts {
		if unescapedDot(h) {
			r.Warnings = append(r.Warnings, fmt.Sprintf("host mask %q has an unescaped '.'", h))
		}
	}
	return r
}

func sizeText(b int64) string {
	switch {
	case b%(1<<20) == 0:
		return fmt.Sprintf("%d MiB", b>>20)
	case b%(1<<10) == 0:
		return fmt.Sprintf("%d KiB", b>>10)
	}
	return fmt.Sprintf("%d bytes", b)
}

func plural(n int, one string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %ss", n, one)
}

// FormatPolicyCheck renders the `policy check` text for a policy and its risk report.
func FormatPolicyCheck(p Policy, r RiskReport) string {
	var b strings.Builder
	line := func(k, format string, a ...any) { fmt.Fprintf(&b, "%-10s %s\n", k, fmt.Sprintf(format, a...)) }
	t := p.Tools
	if t.Mode == "yolo" {
		line("tools", "yolo: no tool rules; every harness tool, run in the workplace")
	} else {
		var notes []string
		file := false
		for _, n := range t.Allow {
			file = file || n == "read_file" || n == "search" || n == "write_file" || n == "apply_patch"
		}
		switch {
		case p.Exec() && file:
			notes = append(notes, "file settings advisory: bash present", "bash masks advisory")
		case p.Exec():
			notes = append(notes, "bash masks advisory")
		default:
			notes = append(notes, "no exec tool")
		}
		line("tools", "allowlist: %s  (%s)", strings.Join(t.Allow, " "), strings.Join(notes, "; "))
	}
	w := p.Workspace
	switch {
	case len(w.WriteScope) == 0:
		line("workspace", "%s; apply accepts nothing", w.Access)
	case w.WriteScope[0] == "*":
		line("workspace", "%s; apply accepts the whole repository", w.Access)
	default:
		line("workspace", "%s; apply accepts %s", w.Access, strings.Join(w.WriteScope, " "))
	}
	n := p.Network
	ports := func() string {
		if n.Ports == nil || n.Ports.Any {
			return "any port"
		}
		var s []string
		for _, p := range n.Ports.Ports {
			s = append(s, strconv.Itoa(p))
		}
		return "ports " + strings.Join(s, " ")
	}
	switch n.Mode {
	case NetNone:
		line("network", "none: no socket, no egress (as v1)")
	case NetModules:
		line("network", "modules: %s; read-only GET/HEAD; covert channel via module paths (rate-limited, logged)", plural(len(n.GoModules), "mask"))
	case NetAllowlist, NetDenylist:
		line("network", "%s: %s, %s; rate-limited, logged", n.Mode, plural(len(n.Hosts), "host mask"), ports())
	case NetAll:
		line("network", "all: every public host, %s; rate-limited, logged", ports())
	}
	l := p.Limits
	cpus := strconv.FormatFloat(l.CPUs, 'f', -1, 64) + " CPUs"
	if l.CPUs == 1 {
		cpus = "1 CPU"
	}
	line("limits", "%s, %d MiB, %d pids, %d s, out %s, disk %d MiB soft", cpus, l.MemoryMiB, l.Pids, l.CallTimeoutS,
		sizeText(l.MaxOutputBytes), l.DiskSoftMiB)
	line("risk", "%s", r.Level)
	for _, s := range r.Reasons {
		line("reason", "%s", s)
	}
	for _, s := range r.Warnings {
		line("warning", "%s", s)
	}
	line("policy id", "%s (sha256 canonical)", r.PolicyID)
	return b.String()
}

// TemplateSpec selects and fills a policy template.
type TemplateSpec struct {
	Name, Project, Worker string
	WriteScope            []string // developer only (required)
	GoModules             []string // developer only (required)
}

// Templates lists the template names.
var Templates = []string{"reviewer", "developer", "yolo-offline"}

// PolicyTemplate generates a complete, explicit policy file. Templates are generators, not inheritance.
func PolicyTemplate(s TemplateSpec) ([]byte, error) {
	p := Policy{Version: 1, Project: s.Project, Worker: s.Worker}
	if s.Name != "developer" && (len(s.WriteScope) > 0 || len(s.GoModules) > 0) {
		return nil, fmt.Errorf("workplace: template %s takes no write scope or go modules", s.Name)
	}
	paths := []string{".*"}
	readers := map[string]ToolSettings{"read_file": {Paths: paths, MaxBytes: 1 << 20}, "search": {Paths: paths, MaxResults: 200}}
	switch s.Name {
	case "reviewer":
		p.Tools = ToolsPolicy{Mode: "allowlist", Allow: []string{"read_file", "search"}, Settings: readers}
		p.Workspace = WorkspacePolicy{Access: "read-only", WriteScope: []string{}}
		p.Network = NetworkPolicy{Mode: NetNone}
		p.Limits = PolicyLimits{CPUs: 1, MemoryMiB: 1024, Pids: 256, CallTimeoutS: 300, MaxOutputBytes: 4 << 20, DiskSoftMiB: 2048}
	case "developer":
		if len(s.WriteScope) == 0 || len(s.GoModules) == 0 {
			return nil, fmt.Errorf("workplace: template developer needs a write scope and go modules")
		}
		var writable []string
		for _, e := range s.WriteScope {
			switch {
			case e == "*":
				writable = append(writable, ".*")
			case strings.HasSuffix(e, "/"):
				writable = append(writable, regexp.QuoteMeta(e)+".*")
			default:
				writable = append(writable, regexp.QuoteMeta(e))
			}
		}
		set := map[string]ToolSettings{
			"write_file":  {Paths: writable, MaxBytes: 1 << 20},
			"apply_patch": {Paths: writable},
			"bash": {Allow: []string{"go (build|test|vet)( .*)?", "git (status|diff|log)( .*)?"},
				Deny: []string{"curl .*", "wget .*"}},
		}
		for k, v := range readers {
			set[k] = v
		}
		p.Tools = ToolsPolicy{Mode: "allowlist", Allow: []string{"read_file", "search", "write_file", "apply_patch", "bash"}, Settings: set}
		p.Workspace = WorkspacePolicy{Access: "read-write", WriteScope: s.WriteScope}
		p.Network = NetworkPolicy{Mode: NetModules, GoModules: s.GoModules,
			Rate: &RatePolicy{RequestsPerMin: 600, MaxConns: 8, BytesPerDay: 2 << 30}}
		p.Limits = PolicyLimits{CPUs: 2, MemoryMiB: 2048, Pids: 512, CallTimeoutS: 600, MaxOutputBytes: 4 << 20, DiskSoftMiB: 4096}
	case "yolo-offline":
		p.Tools = ToolsPolicy{Mode: "yolo"}
		p.Workspace = WorkspacePolicy{Access: "read-write", WriteScope: []string{"*"}}
		p.Network = NetworkPolicy{Mode: NetNone}
		p.Limits = PolicyLimits{CPUs: 2, MemoryMiB: 2048, Pids: 512, CallTimeoutS: 600, MaxOutputBytes: 4 << 20, DiskSoftMiB: 4096}
	default:
		return nil, fmt.Errorf("workplace: unknown template %q (%s)", s.Name, strings.Join(Templates, ", "))
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return nil, err
	}
	if _, err := ParsePolicy(b.Bytes()); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
