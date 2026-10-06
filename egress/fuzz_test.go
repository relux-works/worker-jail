package egress

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

// FuzzReadRequest (E9): the parser never panics, never reads past 8 KiB, and whatever it accepts is a well-formed
// HTTP/1.1 head without a smuggling form. Plain `go test` runs the seeds; `go test -fuzz FuzzReadRequest ./egress` explores.
func FuzzReadRequest(f *testing.F) {
	for _, s := range []string{
		"GET /gomod/golang.org/x/text/@v/list HTTP/1.1\r\nHost: 127.0.0.1:3128\r\n\r\n",
		"HEAD / HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
		"CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n b\r\n\r\n",
		"GET / HTTP/1.1\nHost: h\n\n",
		"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
		"GET http://evil/ HTTP/1.1\r\nHost: evil\r\n\r\n",
		"\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\n" + strings.Repeat("X: y\r\n", 70) + "\r\n",
		"GET / HTTP/1.1\r\nHost: h\r\nX: " + strings.Repeat("a", 9000) + "\r\n\r\n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		r := &countReader{r: strings.NewReader(raw)}
		req, err := readRequest(bufio.NewReaderSize(r, 4096))
		if err != nil {
			if req != nil {
				t.Fatal("request with an error")
			}
			return
		}
		switch {
		case req.HeadBytes > MaxHeaderBytes:
			t.Fatalf("accepted a %d-byte head", req.HeadBytes)
		case !isToken(req.Method) || !isVisible(req.Target):
			t.Fatalf("accepted method %q target %q", req.Method, req.Target)
		case !strings.HasPrefix(raw[req.HeadBytes-4:], "\r\n\r\n"):
			t.Fatalf("head does not end with an empty line: %q", raw[:req.HeadBytes])
		}
		head := strings.ToLower(raw[:req.HeadBytes])
		if strings.Contains(head, "\ntransfer-encoding:") || strings.Count(head, "\ncontent-length:") > 1 ||
			strings.Count(head, "\nhost:") != 1 || strings.Contains(head, "\n ") || strings.Contains(head, "\n\t") {
			t.Fatalf("accepted a smuggling form: %q", raw[:req.HeadBytes])
		}
		if r.n > MaxHeaderBytes+4096 {
			t.Fatalf("read %d bytes for one head", r.n)
		}
	})
}

type countReader struct {
	r io.Reader
	n int
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	return n, err
}

// FuzzModulesPath (E9): the grammar never panics, and whatever it accepts stays under /gomod/ with no traversal or
// encoding, names a known kind, upstream and rest, and carries a module path that re-escapes to the request's.
func FuzzModulesPath(f *testing.F) {
	for _, s := range []string{
		"/gomod/golang.org/x/text/@v/list",
		"/gomod/golang.org/x/text/@v/v0.14.0.zip",
		"/gomod/github.com/!burnt!sushi/toml/@v/v1.3.2.info",
		"/gomod/golang.org/x/text/@v/v0.0.0-20191109021931-daa7c04131f5.mod",
		"/gomod/golang.org/x/text/@latest",
		"/gomod/sumdb/sum.golang.org/supported",
		"/gomod/sumdb/sum.golang.org/lookup/golang.org/x/text@v0.14.0",
		"/gomod/sumdb/sum.golang.org/tile/8/0/x123/456.p/7",
		"/gomod/golang.org/x/text/@v/../../../etc/passwd",
		"/gomod/golang.org%2fx/@v/list",
		"/gomod/sumdb/sum.evil.io/latest",
		"/gomod/golang.org/x/te!!xt/@v/list",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, target string) {
		p, err := parseModulesPath(target)
		if err != nil {
			var ge grammarError
			if !errors.As(err, &ge) {
				t.Fatalf("error of another type: %v", err)
			}
			return
		}
		if len(target) > maxPathBytes || !strings.HasPrefix(target, "/gomod/") || strings.ContainsAny(target, "%?#\\") ||
			strings.Contains(target, "/../") || strings.Contains(target, "/./") || strings.Contains(target, "//") ||
			strings.HasSuffix(target, "/..") || strings.HasSuffix(target, "/") {
			t.Fatalf("accepted %q", target)
		}
		switch p.Upstream {
		case proxyHost:
			if p.Rest != strings.TrimPrefix(target, "/gomod") {
				t.Fatalf("rest %q of %q", p.Rest, target)
			}
		case sumHost, "":
			if !strings.HasPrefix(target, "/gomod/sumdb/sum.golang.org/") {
				t.Fatalf("sumdb upstream for %q", target)
			}
		default:
			t.Fatalf("upstream %q", p.Upstream)
		}
		if p.Module != "" && !strings.Contains(target, escape(p.Module)) {
			t.Fatalf("module %q does not re-escape into %q", p.Module, target)
		}
		if p.Module == "" && p.Kind != kindSupported && p.Kind != kindSumLatest && p.Kind != kindTile {
			t.Fatalf("kind %s without a module: %q", p.Kind, target)
		}
	})
}

// escape is the module proxy's case escaping, the inverse of unescape.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if c := s[i]; c >= 'A' && c <= 'Z' {
			b.WriteByte('!')
			b.WriteByte(c - 'A' + 'a')
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}
