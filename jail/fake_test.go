package jail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
)

// fakeCall is one `docker start` seen by fakeDocker.
type fakeCall struct {
	create         []string
	stdin          io.Reader
	stdout, stderr io.Writer
	killed         chan struct{}
}

// argv returns the command after the image's `timeout -s KILL N`.
func (c *fakeCall) argv() []string {
	for i := range c.create {
		if c.create[i] == "timeout" && i+4 <= len(c.create) && c.create[i+1] == "-s" {
			return c.create[i+4:]
		}
	}
	return nil
}

// fakeDocker is a recording, stateful stand-in for the docker CLI.
type fakeDocker struct {
	mu        sync.Mutex
	calls     [][]string
	volumes   map[string]map[string]string
	busy      map[string]bool
	info      string
	ncpu      string
	imageOut  string
	imageExit int
	createErr string
	ps        string
	onStart   func(c *fakeCall) int
	starts    []*fakeCall
	pending   map[string]*fakeCall
	kills     []string
	nid       int
}

func newFakeDocker() *fakeDocker {
	return &fakeDocker{volumes: map[string]map[string]string{}, busy: map[string]bool{},
		info: "colima-workers\toverlay2\t4", ncpu: "4", imageOut: "null", pending: map[string]*fakeCall{}}
}

type fakeColima struct {
	mounts string
	err    error
}

func (f fakeColima) ProcMounts(context.Context) (string, error) { return f.mounts, f.err }

func (f *fakeDocker) count(verb string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if strings.Join(c, " ") == verb || strings.HasPrefix(strings.Join(c, " "), verb+" ") {
			n++
		}
	}
	return n
}

func labelFilters(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--filter" && strings.HasPrefix(args[i+1], "label=") {
			kv := strings.SplitN(strings.TrimPrefix(args[i+1], "label="), "=", 2)
			m[kv[0]] = kv[1]
		}
	}
	return m
}

func flagValue(args []string, name string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == name {
			return args[i+1]
		}
	}
	return ""
}

func (f *fakeDocker) Run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string(nil), args...))
	switch args[0] {
	case "info":
		defer f.mu.Unlock()
		if strings.Contains(strings.Join(args, " "), ".Name") {
			fmt.Fprintln(stdout, f.info)
		} else {
			fmt.Fprintln(stdout, f.ncpu)
		}
		return 0, nil
	case "image":
		defer f.mu.Unlock()
		if f.imageExit != 0 {
			fmt.Fprintln(stderr, "Error: No such image")
			return f.imageExit, nil
		}
		fmt.Fprintln(stdout, f.imageOut)
		return 0, nil
	case "volume":
		defer f.mu.Unlock()
		return f.volume(args[1:], stdout, stderr), nil
	case "create":
		defer f.mu.Unlock()
		if f.createErr != "" {
			fmt.Fprintln(stderr, f.createErr)
			return 125, nil
		}
		f.nid++
		id := fmt.Sprintf("cid%d", f.nid)
		f.pending[id] = &fakeCall{create: args, killed: make(chan struct{})}
		fmt.Fprintln(stdout, id)
		return 0, nil
	case "start":
		c := f.pending[args[len(args)-1]]
		c.stdin, c.stdout, c.stderr = stdin, stdout, stderr
		f.starts = append(f.starts, c)
		on := f.onStart
		f.mu.Unlock()
		if on == nil {
			io.Copy(io.Discard, stdin)
			return 0, nil
		}
		return on(c), nil
	case "kill":
		defer f.mu.Unlock()
		for _, id := range args[1:] {
			f.kills = append(f.kills, id)
			if c := f.pending[id]; c != nil {
				select {
				case <-c.killed:
				default:
					close(c.killed)
				}
			}
		}
		return 0, nil
	case "ps":
		defer f.mu.Unlock()
		fmt.Fprint(stdout, f.ps)
		return 0, nil
	}
	f.mu.Unlock()
	return 1, fmt.Errorf("fake docker: unexpected %v", args)
}

func (f *fakeDocker) volume(args []string, stdout, stderr io.Writer) int {
	name := args[len(args)-1]
	switch args[0] {
	case "inspect":
		l, ok := f.volumes[name]
		if !ok {
			fmt.Fprintf(stderr, "Error response from daemon: get %s: no such volume\n", name)
			return 1
		}
		b, _ := json.Marshal(l)
		fmt.Fprintln(stdout, string(b))
	case "create":
		l := map[string]string{}
		for i := 1; i+1 < len(args); i++ {
			if args[i] == "--label" {
				kv := strings.SplitN(args[i+1], "=", 2)
				l[kv[0]] = kv[1]
			}
		}
		f.volumes[name] = l
		fmt.Fprintln(stdout, name)
	case "rm":
		if f.busy[name] {
			fmt.Fprintf(stderr, "Error response from daemon: remove %s: volume is in use - [abc]\n", name)
			return 1
		}
		delete(f.volumes, name)
	case "ls":
		filt := labelFilters(args)
		format := flagValue(args, "--format")
		for _, n := range sortedKeys(f.volumes) {
			l := f.volumes[n]
			match := true
			for k, v := range filt {
				if l[k] != v {
					match = false
				}
			}
			if !match {
				continue
			}
			switch format {
			case "":
				fmt.Fprintln(stdout, n)
			case cacheNameFormat:
				fmt.Fprintln(stdout, l[LabelCache])
			case volumeFormat:
				fmt.Fprintf(stdout, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", n, l[LabelKind], l[LabelProject], l[LabelWorker], l[LabelCache], l[LabelBase], l[LabelCreated])
			}
		}
	}
	return 0
}

func sortedKeys(m map[string]map[string]string) []string {
	var k []string
	for n := range m {
		k = append(k, n)
	}
	for i := range k {
		for j := i + 1; j < len(k); j++ {
			if k[j] < k[i] {
				k[i], k[j] = k[j], k[i]
			}
		}
	}
	return k
}

const fixtureHome = "/Users/alexis"

func fixtureMounts(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/vm-proc-mounts.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func newTestJail(t *testing.T, fd *fakeDocker) *Jail {
	t.Helper()
	j, err := New(Config{StateDir: t.TempDir(), Slots: 2, ProjectSlots: 1, Docker: fd, Colima: fakeColima{mounts: fixtureMounts(t)}})
	if err != nil {
		t.Fatal(err)
	}
	j.home = fixtureHome
	return j
}

func addWorkspace(fd *fakeDocker, p, w, base string) {
	fd.volumes[WorkspaceVolume(p, w)] = map[string]string{LabelRoot: "1", LabelKind: KindWorkspace,
		LabelProject: p, LabelWorker: w, LabelBase: base, LabelCreated: "2026-09-29T10:00:00Z"}
}

func addCache(fd *fakeDocker, p, name string) {
	fd.volumes[CacheVolume(p, name)] = map[string]string{LabelRoot: "1", LabelKind: KindCache,
		LabelProject: p, LabelCache: name, LabelCreated: "2026-09-29T10:00:00Z"}
}

func readAll(r io.Reader) []byte {
	var b bytes.Buffer
	io.Copy(&b, r)
	return b.Bytes()
}
