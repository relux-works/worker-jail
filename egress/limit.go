package egress

import (
	"sync"
	"time"

	"github.com/relux-works/worker-jail/jail"
)

// limiter enforces one worker's network.rate: a token bucket of requests_per_min (burst: one minute's worth),
// at most max_conns open connections, and bytes_per_day, which resets at 00:00 UTC. It lives as long as the
// service, so a reload changes the limits but never resets what was spent.
type limiter struct {
	mu     sync.Mutex
	rate   jail.RatePolicy
	tokens float64
	last   time.Time
	conns  int64
	day    string
	bytes  int64
}

func newLimiter(r jail.RatePolicy, now time.Time) *limiter {
	return &limiter{rate: r, tokens: float64(r.RequestsPerMin), last: now, day: now.UTC().Format(time.DateOnly)}
}

// setRate adopts a reloaded policy's limits; the bucket is clipped to the new burst.
func (l *limiter) setRate(r jail.RatePolicy) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rate = r
	l.tokens = min(l.tokens, float64(r.RequestsPerMin))
}

func (l *limiter) rollDay(now time.Time) {
	if d := now.UTC().Format(time.DateOnly); d != l.day {
		l.day, l.bytes = d, 0
	}
}

// conn takes a connection slot; false when max_conns are open.
func (l *limiter) conn() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.conns >= l.rate.MaxConns {
		return false
	}
	l.conns++
	return true
}

func (l *limiter) release() {
	l.mu.Lock()
	l.conns--
	l.mu.Unlock()
}

// request takes one token and requires some of today's bytes to be left.
func (l *limiter) request(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollDay(now)
	per := float64(l.rate.RequestsPerMin)
	l.tokens = min(per, l.tokens+now.Sub(l.last).Minutes()*per)
	l.last = now
	if l.tokens < 1 || l.bytes >= l.rate.BytesPerDay {
		return false
	}
	l.tokens--
	return true
}

// spend counts n bytes against today's budget; false (and nothing counted) if they do not fit.
func (l *limiter) spend(n int64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollDay(now)
	if n > l.rate.BytesPerDay-l.bytes {
		return false
	}
	l.bytes += n
	return true
}
