package egress

import (
	"encoding/json"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Entry is one request's JSON log line (egress.md §5). It never holds a body or a header.
type Entry struct {
	TS       string `json:"ts"`
	Project  string `json:"project"`
	Worker   string `json:"worker"`
	PolicyID string `json:"policy_id"`
	Mode     string `json:"mode"`
	Handler  string `json:"handler"`
	Method   string `json:"method"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Path     string `json:"path"`
	// Plain HTTP only: the path is its first 256 bytes, query stripped; these are the full path's length and sha256.
	PathLen    int    `json:"path_len,omitempty"`
	PathSHA256 string `json:"path_sha256,omitempty"`
	Decision   string `json:"decision"` // allow | deny | error
	Code       string `json:"code"`
	Status     int    `json:"status"`
	BytesIn    int64  `json:"bytes_in"`
	BytesOut   int64  `json:"bytes_out"`
	DurMS      int64  `json:"dur_ms"`
	Cache      string `json:"cache"` // hit | miss | ""
	IP         string `json:"ip"`
	// Generic exchanges only: why the tunnel or the response stream ended (eof, idle, lifetime, bytes, error).
	End string `json:"end,omitempty"`
}

// event is a service log line: a policy loaded or refused, a listener opened or closed, a panic.
type event struct {
	TS       string `json:"ts"`
	Event    string `json:"event"`
	Project  string `json:"project,omitempty"`
	Worker   string `json:"worker,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
	Mode     string `json:"mode,omitempty"`
	File     string `json:"file,omitempty"`
	Error    string `json:"error,omitempty"`
}

// sinkStall is how long a log write may block before new connections are refused.
const sinkStall = 5 * time.Second

// logger writes JSON lines to the sink, one at a time. A write that has been blocked for sinkStall makes
// stalled() true, and the service refuses new connections until the write returns.
type logger struct {
	mu        sync.Mutex
	w         io.Writer
	busySince atomic.Int64 // unix nanoseconds of the write in progress, 0 if none
	now       func() time.Time
}

func (l *logger) write(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	l.busySince.Store(l.now().UnixNano())
	l.w.Write(b)
	l.busySince.Store(0)
}

func (l *logger) stalled() bool {
	s := l.busySince.Load()
	return s != 0 && l.now().Sub(time.Unix(0, s)) >= sinkStall
}

func (l *logger) event(e event) {
	e.TS = l.now().UTC().Format(time.RFC3339Nano)
	l.write(e)
}
