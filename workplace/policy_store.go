package workplace

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

func (j *Workplace) policyPath(r Ref) string {
	return filepath.Join(j.state, "policies", r.Project+"."+r.Worker+".json")
}

// SetPolicy validates data as r's policy and stores it (0600, atomic rename).
// It refuses a policy for another target, CRITICAL without AcceptRisk CRITICAL and HIGH without a note.
// A policy with egress (modules, allowlist, denylist, all) is then delivered to the egress service (egress.md §6): the
// whole file is written into the policy volume by a hardened call, the service is signalled, and SetPolicy waits until
// it reports the stored id. A failure there is ErrEgressUnavailable; the policy stays stored, and Run fails closed until
// the service confirms it.
// A policy that replaces one with egress withdraws the old one from the service.
func (j *Workplace) SetPolicy(ctx context.Context, r Ref, data []byte, o SetPolicyOptions) (StoredPolicy, error) {
	if err := migrationGuard(j.state); err != nil {
		return StoredPolicy{}, err
	}
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
	if err := riskGate(p, risk.Level, o.AcceptRisk); err != nil {
		return sp, err
	}
	prev, _ := j.LoadPolicy(r)
	sp = StoredPolicy{Policy: p, Risk: risk, Path: j.policyPath(r), Raw: data}
	if err := writeAtomic(sp.Path, data); err != nil {
		return StoredPolicy{}, fmt.Errorf("workplace: store policy: %w", err)
	}
	switch {
	case p.Network.Mode != NetNone:
		if err := j.deliverEgress(ctx, r, data, p); err != nil {
			if !errors.Is(err, ErrEgressUnavailable) {
				err = fmt.Errorf("%w: %w", ErrEgressUnavailable, err)
			}
			return sp, fmt.Errorf("workplace: policy %s stored, egress not confirmed: %w", p.ID(), err)
		}
	case prev.Network.Mode != "" && prev.Network.Mode != NetNone:
		if err := j.withdrawEgress(ctx, r); err != nil {
			sp.EgressWarning = fmt.Sprintf("the previous policy could not be withdrawn from the egress service: %v", err)
		}
	}
	return sp, nil
}

// riskGate is design-owner decision 7: CRITICAL needs an explicit accept-risk CRITICAL, HIGH needs a note.
func riskGate(p Policy, level, accept Risk) error {
	switch {
	case level >= RiskCritical && accept != RiskCritical:
		return fmt.Errorf("%w: %s needs an explicit accept-risk CRITICAL", ErrRiskExceeded, level)
	case level == RiskHigh && p.Note == "":
		return fmt.Errorf("%w: %s needs a note recording the reason", ErrRiskExceeded, level)
	}
	return nil
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
func (j *Workplace) LoadPolicy(r Ref) (Policy, error) {
	sp, err := j.ShowPolicy(r)
	return sp.Policy, err
}

// ShowPolicy returns r's stored policy with its id and risk.
func (j *Workplace) ShowPolicy(r Ref) (StoredPolicy, error) {
	if err := migrationGuard(j.state); err != nil {
		return StoredPolicy{}, err
	}
	if err := r.validate(); err != nil {
		return StoredPolicy{}, err
	}
	path := j.policyPath(r)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return StoredPolicy{}, fmt.Errorf("%w: %s.%s", ErrNoPolicy, r.Project, r.Worker)
	}
	if err != nil {
		return StoredPolicy{}, fmt.Errorf("workplace: read policy: %w", err)
	}
	p, err := ParsePolicy(data)
	if err != nil {
		return StoredPolicy{}, fmt.Errorf("workplace: stored policy %s: %w", path, err)
	}
	if err := matchTarget(p, r); err != nil {
		return StoredPolicy{}, fmt.Errorf("workplace: stored policy %s: %w", path, err)
	}
	return StoredPolicy{Policy: p, Risk: EffectiveRisk(p), Path: path, Raw: data}, nil
}

// RemovePolicy deletes r's stored policy. Deprovision keeps it, so a later provision does not silently drop it.
// A policy with egress is first withdrawn from the egress service; if that fails, the stored file is kept.
func (j *Workplace) RemovePolicy(r Ref) error {
	if err := migrationGuard(j.state); err != nil {
		return err
	}
	if err := r.validate(); err != nil {
		return err
	}
	if p, err := j.LoadPolicy(r); err == nil && p.Network.Mode != NetNone {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := j.withdrawEgress(ctx, r); err != nil {
			return fmt.Errorf("workplace: withdraw %s.%s from egress (the policy is kept): %w", r.Project, r.Worker, err)
		}
	}
	err := os.Remove(j.policyPath(r))
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s.%s", ErrNoPolicy, r.Project, r.Worker)
	}
	return err
}
