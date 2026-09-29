package jail

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func freeCount(t *testing.T, paths []string) int {
	t.Helper()
	n := 0
	for _, p := range paths {
		rel, ok, err := tryLock(p)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			n++
			rel()
		}
	}
	return n
}

// At most n holders at once; the (n+1)th waits, proceeds after a release, and stops on ctx cancel.
func TestSlotsBoundAndRelease(t *testing.T) {
	paths, err := slotPaths(t.TempDir(), 2)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	r1, err := lockAny(ctx, paths)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := lockAny(ctx, paths) // control: a second holder fits
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	if _, err := lockAny(short, paths); err == nil {
		t.Fatal("third holder acquired a slot while two of two are held")
	}
	got := make(chan func(), 1)
	go func() {
		r, err := lockAny(ctx, paths)
		if err != nil {
			t.Error(err)
		}
		got <- r
	}()
	select {
	case <-got:
		t.Fatal("waiter proceeded before any release")
	case <-time.After(100 * time.Millisecond):
	}
	r1()
	select {
	case r3 := <-got:
		r3()
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not proceed after a release")
	}
	r2()
	if n := freeCount(t, paths); n != 2 {
		t.Fatalf("free after releases = %d, want 2", n)
	}
}

// A waiting call holds no global slot while it waits for a project slot, and proceeds once the project slot frees.
func TestSlotsProjectBeforeGlobal(t *testing.T) {
	fd := newFakeDocker()
	j := newTestJail(t, fd) // N=2, M=1
	ctx := context.Background()
	rel1, err := j.acquireSlots(ctx, "p1")
	if err != nil {
		t.Fatal(err)
	}
	global, _ := slotPaths(filepath.Join(j.state, "slots", "global"), 2)
	if n := freeCount(t, global); n != 1 {
		t.Fatalf("control: first holder should take one global slot, free=%d", n)
	}
	done := make(chan func(), 1)
	go func() {
		r, err := j.acquireSlots(ctx, "p1")
		if err != nil {
			t.Error(err)
		}
		done <- r
	}()
	time.Sleep(150 * time.Millisecond)
	if n := freeCount(t, global); n != 1 {
		t.Fatalf("waiter holds a global slot while waiting for its project slot (free=%d)", n)
	}
	// Another project is not blocked by p1's queue.
	other, err := j.acquireSlots(ctx, "p2")
	if err != nil {
		t.Fatal(err)
	}
	other()
	rel1()
	select {
	case r := <-done:
		r()
	case <-time.After(2 * time.Second):
		t.Fatal("waiter did not proceed")
	}
}

// With Slots=0 the VM's CPU count is queried once and M defaults to ceil(N/2).
func TestSlotCountsFromVM(t *testing.T) {
	fd := newFakeDocker()
	fd.ncpu = "5"
	j := newTestJail(t, fd)
	j.slots, j.projectSlots = 0, 0
	for range 2 {
		n, m, err := j.slotCounts(context.Background())
		if err != nil || n != 5 || m != 3 {
			t.Fatalf("got %d %d %v, want 5 3", n, m, err)
		}
	}
	if c := fd.count("info"); c != 1 {
		t.Fatalf("docker info called %d times, want 1", c)
	}
	bad := newFakeDocker()
	bad.ncpu = "zero"
	j2 := newTestJail(t, bad)
	j2.slots = 0
	if _, _, err := j2.slotCounts(context.Background()); err == nil {
		t.Fatal("unparsable NCPU accepted")
	}
}
