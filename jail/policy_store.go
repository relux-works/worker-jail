package jail

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// SetPolicyOptions tunes SetPolicy.
type SetPolicyOptions struct {
	// AcceptRisk must be RiskCritical to store a CRITICAL policy (design-owner decision 7).
	AcceptRisk Risk
}

// StoredPolicy is a policy as stored on the host.
type StoredPolicy struct {
	Policy Policy
	Risk   RiskReport
	Path   string
	Raw    []byte // the file as stored
}

func (j *Jail) policyPath(r Ref) string {
	return filepath.Join(j.state, "policies", r.Project+"."+r.Worker+".json")
}

// SetPolicy validates data as r's policy and stores it (0600, atomic rename).
// It refuses a policy for another target, CRITICAL without AcceptRisk CRITICAL, HIGH without a note,
// and, until egress arrives in v2.1, any network mode other than none.
func (j *Jail) SetPolicy(ctx context.Context, r Ref, data []byte, o SetPolicyOptions) (StoredPolicy, error) {
	var sp StoredPolicy
	if err := r.validate(); err != nil {
		return sp, err
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return sp, err
	}
	if err := matchTarget(p, r); err != nil {
		return sp, err
	}
	risk := EffectiveRisk(p)
	switch {
	case risk.Level >= RiskCritical && o.AcceptRisk != RiskCritical:
		return sp, fmt.Errorf("%w: %s needs an explicit accept-risk CRITICAL", ErrRiskExceeded, risk.Level)
	case risk.Level == RiskHigh && p.Note == "":
		return sp, fmt.Errorf("%w: %s needs a note recording the reason", ErrRiskExceeded, risk.Level)
	}
	if p.Network.Mode != NetNone {
		return sp, fmt.Errorf("%w (network.mode %s)", ErrEgressUnavailable, p.Network.Mode)
	}
	sp = StoredPolicy{Policy: p, Risk: risk, Path: j.policyPath(r), Raw: data}
	if err := writeAtomic(sp.Path, data); err != nil {
		return StoredPolicy{}, fmt.Errorf("jail: store policy: %w", err)
	}
	return sp, nil
}

func matchTarget(p Policy, r Ref) error {
	if p.Project != r.Project {
		return perr("project", "must equal the target %q, not %q", r.Project, p.Project)
	}
	if p.Worker != r.Worker {
		return perr("worker", "must equal the target %q, not %q", r.Worker, p.Worker)
	}
	return nil
}

// LoadPolicy reads and validates r's stored policy. The harness uses it to expose tools and log the id.
func (j *Jail) LoadPolicy(r Ref) (Policy, error) {
	sp, err := j.ShowPolicy(r)
	return sp.Policy, err
}

// ShowPolicy returns r's stored policy with its id and risk.
func (j *Jail) ShowPolicy(r Ref) (StoredPolicy, error) {
	if err := r.validate(); err != nil {
		return StoredPolicy{}, err
	}
	path := j.policyPath(r)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return StoredPolicy{}, fmt.Errorf("%w: %s.%s", ErrNoPolicy, r.Project, r.Worker)
	}
	if err != nil {
		return StoredPolicy{}, fmt.Errorf("jail: read policy: %w", err)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return StoredPolicy{}, fmt.Errorf("jail: stored policy %s: %w", path, err)
	}
	if err := matchTarget(p, r); err != nil {
		return StoredPolicy{}, fmt.Errorf("jail: stored policy %s: %w", path, err)
	}
	return StoredPolicy{Policy: p, Risk: EffectiveRisk(p), Path: path, Raw: data}, nil
}

// RemovePolicy deletes r's stored policy. Deprovision keeps it, so a later provision does not silently drop it.
func (j *Jail) RemovePolicy(r Ref) error {
	if err := r.validate(); err != nil {
		return err
	}
	err := os.Remove(j.policyPath(r))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s.%s", ErrNoPolicy, r.Project, r.Worker)
	}
	return err
}

// servedPolicy loads r's policy for Provision and Run: it must exist, be valid and need no egress (v2.0).
func (j *Jail) servedPolicy(r Ref) (Policy, error) {
	p, err := j.LoadPolicy(r)
	if err != nil {
		return p, err
	}
	if p.Network.Mode != NetNone {
		return p, fmt.Errorf("%w (network.mode %s)", ErrEgressUnavailable, p.Network.Mode)
	}
	return p, nil
}
