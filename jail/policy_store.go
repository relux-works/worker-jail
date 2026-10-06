package jail

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
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
	// EgressWarning is set when a policy without egress replaced one with egress and the old policy could not be
	// withdrawn from the egress service. No call of the worker mounts its socket any more; the listener is stale.
	EgressWarning string
}

func (j *Jail) policyPath(r Ref) string {
	return filepath.Join(j.state, "policies", r.Project+"."+r.Worker+".json")
}

// SetPolicy validates data as r's policy and stores it (0600, atomic rename).
// It refuses a policy for another target, CRITICAL without AcceptRisk CRITICAL, HIGH without a note,
// and the generic network modes (allowlist, denylist, all), which arrive in a later v2.1 part.
// A modules policy is then delivered to the egress service (egress.md §6): the whole file is written into the policy
// volume by a hardened call, the service is signalled, and SetPolicy waits until it reports the stored id. A failure
// there is ErrEgressUnavailable; the policy stays stored, and Run fails closed until the service confirms it.
// A policy that replaces one with egress withdraws the old one from the service.
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
	if err := servedMode(p); err != nil {
		return sp, err
	}
	prev, _ := j.LoadPolicy(r)
	sp = StoredPolicy{Policy: p, Risk: risk, Path: j.policyPath(r), Raw: data}
	if err := writeAtomic(sp.Path, data); err != nil {
		return StoredPolicy{}, fmt.Errorf("jail: store policy: %w", err)
	}
	switch {
	case p.Network.Mode == NetModules:
		if err := j.deliverEgress(ctx, r, data, p); err != nil {
			if !errors.Is(err, ErrEgressUnavailable) {
				err = fmt.Errorf("%w: %w", ErrEgressUnavailable, err)
			}
			return sp, fmt.Errorf("jail: policy %s stored, egress not confirmed: %w", p.ID(), err)
		}
	case prev.Network.Mode != "" && prev.Network.Mode != NetNone:
		if err := j.withdrawEgress(ctx, r); err != nil {
			sp.EgressWarning = fmt.Sprintf("the previous policy could not be withdrawn from the egress service: %v", err)
		}
	}
	return sp, nil
}

// servedMode refuses the network modes this version does not serve: the generic ones (allowlist, denylist, all).
func servedMode(p Policy) error {
	switch p.Network.Mode {
	case NetNone, NetModules:
		return nil
	}
	return fmt.Errorf("%w: network.mode %s: the generic modes (allowlist, denylist, all) arrive in a later v2.1 part; "+
		"v2.1 part A serves none and modules", ErrEgressUnavailable, p.Network.Mode)
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
// A policy with egress is first withdrawn from the egress service; if that fails, the stored file is kept.
func (j *Jail) RemovePolicy(r Ref) error {
	if err := r.validate(); err != nil {
		return err
	}
	if p, err := j.LoadPolicy(r); err == nil && p.Network.Mode != NetNone {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := j.withdrawEgress(ctx, r); err != nil {
			return fmt.Errorf("jail: withdraw %s.%s from egress (the policy is kept): %w", r.Project, r.Worker, err)
		}
	}
	err := os.Remove(j.policyPath(r))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s.%s", ErrNoPolicy, r.Project, r.Worker)
	}
	return err
}

// servedPolicy loads r's policy for Provision and Run: it must exist, be valid and have a mode this version serves.
func (j *Jail) servedPolicy(r Ref) (Policy, error) {
	p, err := j.LoadPolicy(r)
	if err != nil {
		return p, err
	}
	return p, servedMode(p)
}
