package workplace

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// tryLock takes an exclusive non-blocking flock on path. ok=false if it is held elsewhere.
func tryLock(path string) (release func(), ok bool, err error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if err == syscall.EWOULDBLOCK {
			return nil, false, nil
		}
		return nil, false, err
	}
	return func() { f.Close() }, true, nil
}

// lockAny takes the first free lock among paths, retrying every 20-80 ms until ctx is done.
func lockAny(ctx context.Context, paths []string) (func(), error) {
	for {
		for _, p := range paths {
			rel, ok, err := tryLock(p)
			if err != nil {
				return nil, fmt.Errorf("workplace: lock %s: %w", p, err)
			}
			if ok {
				return rel, nil
			}
		}
		t := time.NewTimer(time.Duration(20+rand.IntN(61)) * time.Millisecond)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, fmt.Errorf("workplace: waiting for lock: %w", ctx.Err())
		case <-t.C:
		}
	}
}

func slotPaths(dir string, n int) ([]string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := make([]string, n)
	for i := range p {
		p[i] = filepath.Join(dir, strconv.Itoa(i)+".lock")
	}
	return p, nil
}

// slotCounts returns N and M, asking the VM for its CPU count once when needed.
func (j *Workplace) slotCounts(ctx context.Context) (int, int, error) {
	j.slotMu.Lock()
	defer j.slotMu.Unlock()
	if j.slots == 0 {
		out, errb, exit, err := j.dockerOut(ctx, nil, "info", "--format", "{{.NCPU}}")
		if err != nil {
			return 0, 0, fmt.Errorf("workplace: docker info: %w", err)
		}
		n, perr := strconv.Atoi(strings.TrimSpace(out))
		if exit != 0 || perr != nil || n < 1 {
			return 0, 0, fmt.Errorf("workplace: docker info: cannot read NCPU: %s", errb)
		}
		j.slots = n
	}
	m := j.projectSlots
	if m == 0 {
		m = (j.slots + 1) / 2
	}
	return j.slots, m, nil
}

// acquireSlots takes a project slot, then a global one. release frees them in reverse order.
func (j *Workplace) acquireSlots(ctx context.Context, project string) (func(), error) {
	n, m, err := j.slotCounts(ctx)
	if err != nil {
		return nil, err
	}
	pp, err := slotPaths(filepath.Join(j.state, "slots", "p."+project), m)
	if err != nil {
		return nil, err
	}
	gp, err := slotPaths(filepath.Join(j.state, "slots", "global"), n)
	if err != nil {
		return nil, err
	}
	relP, err := lockAny(ctx, pp)
	if err != nil {
		return nil, err
	}
	relG, err := lockAny(ctx, gp)
	if err != nil {
		relP()
		return nil, err
	}
	return func() { relG(); relP() }, nil
}

func (j *Workplace) lockPath(ctx context.Context, name string) (func(), error) {
	return lockAny(ctx, []string{filepath.Join(j.state, "locks", name+".lock")})
}
