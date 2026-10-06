package jail

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// v1 and v2.0 base images: labels without the egress relay.
var noRelayLabels = []string{`null`, `{"ai.relux.worker-jail.base-image":"1"}`, `{"ai.relux.worker-jail.egress-relay":"nc"}`}

// relayPolicies are the egress policies the relay tests cover: modules and allowlist (with the note HIGH needs).
func relayPolicies(t *testing.T) map[string][]byte {
	return map[string][]byte{
		NetModules:   modulesPolicy(t, "p1", "w1"),
		NetAllowlist: genericPolicyJ(t, "p1", "w1", NetAllowlist, set("note", "registry only")),
	}
}

// Provision of a modules or allowlist worker refuses an image without the egress-relay label with ErrImageNoRelay,
// naming the image and base:2, before any volume or container exists; the same jail provisions once the image carries
// the label (a refusal is not cached).
func TestProvisionImageRelay(t *testing.T) {
	for mode, data := range relayPolicies(t) {
		for _, labels := range noRelayLabels {
			repo := newRepo(t)
			fd := egressFake(t)
			fd.onStart = provisionStart(t, 1, 0)
			fd.replies["inspect"] = fakeReply{out: hardenedEgress}
			fd.imageLabels = labels
			j := newTestJail(t, fd)
			storePolicy(t, j, "p1", "w1", data)
			_, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo})
			if !errors.Is(err, ErrImageNoRelay) || !strings.Contains(err.Error(), DefaultImage) ||
				!strings.Contains(err.Error(), "FROM worker-jail/base:2") {
				t.Errorf("%s %s: %v", mode, labels, err)
			}
			if _, ok := fd.volumes["wj.p1.w1"]; ok || fd.count("volume create") != 0 || fd.count("create") != 0 {
				t.Errorf("%s %s: something was created", mode, labels)
			}

			fd.imageLabels = baseV2Labels
			if ws, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo}); err != nil ||
				ws.PolicyID != policyID(t, data) {
				t.Errorf("%s with the label: %+v %v", mode, ws, err)
			}
		}
	}
}

// A none policy provisions and runs with an image that has no labels at all (v1 and v2.0 images keep serving offline
// workers), and neither Provision nor Run inspects the image's labels for it.
func TestImageRelayNotNeededForNone(t *testing.T) {
	repo := newRepo(t)
	fd := newFakeDocker()
	fd.onStart = provisionStart(t, 1, 0)
	fd.imageLabels = "null"
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "w1", testPolicy("p1", "w1"))
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w1"}, Repo: repo}); err != nil {
		t.Fatal(err)
	}
	fd.onStart = nil
	if _, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}}); err != nil {
		t.Fatal(err)
	}
	// The only label inspection is doctor's informational one, from Provision.
	if n := fd.count("image inspect --format {{json .Config.Labels}}"); n != 1 {
		t.Fatalf("%d label inspections", n)
	}
}

// Run of a modules or allowlist worker refuses an image without the egress-relay label with ErrImageNoRelay before any
// container is created; with the label it runs, and the positive answer is cached: a second call inspects nothing.
func TestRunImageRelay(t *testing.T) {
	for mode, data := range relayPolicies(t) {
		for _, labels := range noRelayLabels {
			fd, j := genericWorkspace(t, data)
			fd.imageLabels = labels
			_, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}})
			if !errors.Is(err, ErrImageNoRelay) || !strings.Contains(err.Error(), DefaultImage) ||
				!strings.Contains(err.Error(), "FROM worker-jail/base:2") || fd.count("create") != 0 {
				t.Errorf("%s %s: %v, %d creates", mode, labels, err, fd.count("create"))
			}
		}

		fd, j := genericWorkspace(t, data)
		for i := 0; i < 2; i++ {
			if _, err := j.Run(context.Background(), Ref{"p1", "w1"}, RunSpec{Argv: []string{"true"}}); err != nil {
				t.Fatalf("%s with the label: %v", mode, err)
			}
		}
		if n := fd.count("image inspect"); n != 1 || fd.count("create") != 2 {
			t.Errorf("%s: %d inspections, %d creates", mode, n, fd.count("create"))
		}
	}
}

// Doctor reports the image's relay as the check relay: informational (passing) without a networked policy even
// when the label is missing, failing with ErrDoctor once a stored policy needs egress, and passing with the label.
func TestDoctorImageRelay(t *testing.T) {
	relayCheck := func(rep DoctorReport) Check {
		for _, c := range rep.Checks {
			if c.Name == "relay" {
				return c
			}
		}
		t.Fatalf("no relay check in %+v", rep)
		return Check{}
	}
	fd := egressFake(t)
	fd.replies["inspect"] = fakeReply{out: hardenedEgress}
	fd.imageLabels = "null"
	j := newTestJail(t, fd)
	rep, err := j.Doctor(context.Background())
	if c := relayCheck(rep); err != nil || !c.OK || !strings.Contains(c.Detail, "lacks") {
		t.Fatalf("offline, no label: %+v %v", c, err)
	}

	storePolicy(t, j, "p1", "w1", modulesPolicy(t, "p1", "w1"))
	rep, err = j.Doctor(context.Background())
	if c := relayCheck(rep); !errors.Is(err, ErrDoctor) || c.OK || !strings.Contains(err.Error(), "relay: ") ||
		!strings.Contains(err.Error(), "worker-jail/base:2") {
		t.Fatalf("modules, no label: %+v %v", c, err)
	}

	fd.imageLabels = baseV2Labels
	rep, err = j.Doctor(context.Background())
	if c := relayCheck(rep); err != nil || !c.OK || !strings.Contains(c.Detail, "socat") {
		t.Fatalf("modules, label: %+v %v", c, err)
	}
}

// One worker's egress policy never blocks an offline worker: with a modules policy stored for w-net, an image without
// the relay label and no egress service, an offline worker (none policy) still provisions. Control: the operator's
// Doctor fails on the relay check for the same state, and provisioning w-net itself is refused with ErrImageNoRelay.
func TestOfflineWorkerNotBlockedByOthersEgress(t *testing.T) {
	repo := newRepo(t)
	fd := newFakeDocker()
	fd.onStart = provisionStart(t, 1, 0)
	fd.imageLabels = "null"
	j := newTestJail(t, fd)
	storePolicy(t, j, "p1", "w-net", modulesPolicy(t, "p1", "w-net"))
	storePolicy(t, j, "p1", "w-off", testPolicy("p1", "w-off"))
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w-off"}, Repo: repo}); err != nil {
		t.Fatalf("offline worker blocked: %v", err)
	}
	if _, err := j.Doctor(context.Background()); !errors.Is(err, ErrDoctor) || !strings.Contains(err.Error(), "relay") {
		t.Errorf("control: operator doctor passed: %v", err)
	}
	if _, err := j.Provision(context.Background(), ProvisionSpec{Ref: Ref{"p1", "w-net"}, Repo: repo}); !errors.Is(err, ErrImageNoRelay) {
		t.Errorf("control: egress worker provisioned on an image without the relay: %v", err)
	}
}
