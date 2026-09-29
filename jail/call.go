package jail

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// cappedWriter forwards the first max bytes to w, counts the rest and signals overflow once.
type cappedWriter struct {
	mu       sync.Mutex
	w        io.Writer
	max      int64
	n        int64
	werr     error
	overflow chan<- struct{}
	once     *sync.Once
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	keep := int64(len(p))
	if room := c.max - c.n; keep > room {
		keep = max(room, 0)
		c.once.Do(func() { c.overflow <- struct{}{} })
	}
	if keep > 0 && c.werr == nil {
		_, c.werr = c.w.Write(p[:keep])
	}
	c.n += int64(len(p))
	return len(p), nil
}

// killWait bounds how long call waits for `docker start` to return after `docker kill`.
var killWait = 30 * time.Second

// call runs one container: slots, create, start -a -i, caps, kill. stdout goes to out (capped at maxOut).
func (j *Jail) call(ctx context.Context, s callSpec, stdin io.Reader, out io.Writer, maxOut int) (Result, []byte, error) {
	var res Result
	s.Name, s.Image, s.Limits = newCallName(), j.image, j.limits
	args, err := createArgs(s)
	if err != nil {
		return res, nil, err
	}
	if maxOut <= 0 {
		maxOut = DefaultMaxOutput
	}
	q := time.Now()
	release, err := j.acquireSlots(ctx, s.Project)
	if err != nil {
		return res, nil, err
	}
	defer release()
	res.QueueWait = time.Since(q)
	start := time.Now()
	defer func() { res.Duration = time.Since(start) }()

	cid, errb, exit, err := j.dockerOut(ctx, nil, args...)
	if err != nil {
		return res, nil, fmt.Errorf("jail: docker create: %w", err)
	}
	if exit != 0 {
		return res, nil, fmt.Errorf("jail: docker create: exit %d: %s", exit, errb)
	}
	id := strings.TrimSpace(cid)
	if id == "" {
		return res, nil, fmt.Errorf("jail: docker create returned no id")
	}
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	var errBuf bytes.Buffer
	overflow := make(chan struct{}, 2)
	once := &sync.Once{}
	ow := &cappedWriter{w: out, max: int64(maxOut), overflow: overflow, once: once}
	ew := &cappedWriter{w: &errBuf, max: int64(maxOut), overflow: overflow, once: once}
	type startRes struct {
		exit int
		err  error
	}
	done := make(chan startRes, 1)
	go func() {
		// Not bound to ctx: cancellation goes through docker kill, never by killing the CLI.
		e, err := j.docker.Run(context.WithoutCancel(ctx), []string{"start", "-a", "-i", id}, stdin, ow, ew)
		done <- startRes{e, err}
	}()
	timer := time.NewTimer(s.Timeout)
	defer timer.Stop()
	var r startRes
	var ctxErr error
	stopped := true
	select {
	case r = <-done:
	case <-timer.C:
		res.TimedOut, stopped = true, false
	case <-overflow:
		res.Truncated, stopped = true, false
	case <-ctx.Done():
		ctxErr, stopped = ctx.Err(), false
	}
	if !stopped {
		j.kill(id)
		select {
		case r = <-done:
		case <-time.After(killWait):
			return res, nil, fmt.Errorf("jail: container %s did not stop after kill", id)
		}
	}
	res.Exit = r.exit
	res.Stderr = errBuf.Bytes()
	if ow.n > ow.max || ew.n > ew.max {
		res.Truncated = true
	}
	if ctxErr != nil {
		return res, res.Stderr, fmt.Errorf("jail: call cancelled: %w", ctxErr)
	}
	if r.err != nil {
		j.kill(id)
		return res, res.Stderr, fmt.Errorf("jail: docker start: %w", r.err)
	}
	if ow.werr != nil {
		return res, res.Stderr, fmt.Errorf("jail: writing output: %w", ow.werr)
	}
	return res, res.Stderr, nil
}

func (j *Jail) kill(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	j.dockerOut(ctx, nil, "kill", id) // "No such container" is fine: it already ended.
}
