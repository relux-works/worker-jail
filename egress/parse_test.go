package egress

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"testing"
)

func parse(raw string) (*Request, error) {
	return readRequest(bufio.NewReaderSize(strings.NewReader(raw), 4096))
}

// The parser accepts well-formed HTTP/1.1 heads and refuses every smuggling and malformed form (E9), each next to
// the accepted form it deviates from.
func TestReadRequest(t *testing.T) {
	ok := "GET /gomod/x HTTP/1.1\r\nHost: 127.0.0.1:3128\r\nUser-Agent: Go-http-client/1.1\r\n\r\n"
	big := "GET / HTTP/1.1\r\nHost: h\r\nX: " + strings.Repeat("a", MaxHeaderBytes) + "\r\n\r\n"
	many := "GET / HTTP/1.1\r\nHost: h\r\n" + strings.Repeat("X: y\r\n", maxHeaders) + "\r\n"
	cases := []struct {
		name, raw string
		want      error // nil: accepted
	}{
		{"control: origin form", ok, nil},
		{"control: Content-Length 0", "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\n\r\n", nil},
		{"control: CONNECT authority form", "CONNECT proxy.golang.org:443 HTTP/1.1\r\nHost: proxy.golang.org:443\r\n\r\n", nil},
		{"control: just under 8 KiB", "GET / HTTP/1.1\r\nHost: h\r\nX: " + strings.Repeat("a", MaxHeaderBytes-40) + "\r\n\r\n", nil},
		{"duplicate Content-Length", "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n", errMalformed},
		{"Transfer-Encoding with Content-Length", "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n", errMalformed},
		{"Transfer-Encoding alone", "GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n", errMalformed},
		{"Transfer-Encoding obfuscated", "GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding : chunked\r\n\r\n", errMalformed},
		{"signed Content-Length", "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: +1\r\n\r\n", errMalformed},
		{"Content-Length with leading zero", "GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 01\r\n\r\n", errMalformed},
		{"bare LF", "GET / HTTP/1.1\nHost: h\n\n", errMalformed},
		{"bare LF in header", "GET / HTTP/1.1\r\nHost: h\nX: y\r\n\r\n", errMalformed},
		{"obs-fold", "GET / HTTP/1.1\r\nHost: h\r\nX: a\r\n b\r\n\r\n", errMalformed},
		{"no Host", "GET / HTTP/1.1\r\nX: y\r\n\r\n", errMalformed},
		{"two Hosts", "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", errMalformed},
		{"HTTP/1.0", "GET / HTTP/1.0\r\nHost: h\r\n\r\n", errMalformed},
		{"HTTP/2 preface", "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", errMalformed},
		{"lower-case version", "GET / http/1.1\r\nHost: h\r\n\r\n", errMalformed},
		{"two spaces", "GET  / HTTP/1.1\r\nHost: h\r\n\r\n", errMalformed},
		{"tab in target", "GET /a\tb HTTP/1.1\r\nHost: h\r\n\r\n", errMalformed},
		{"non-ASCII target", "GET /\xc3\xa9 HTTP/1.1\r\nHost: h\r\n\r\n", errMalformed},
		{"leading empty line", "\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n", errMalformed},
		{"space before colon", "GET / HTTP/1.1\r\nHost : h\r\n\r\n", errMalformed},
		{"control byte in value", "GET / HTTP/1.1\r\nHost: h\r\nX: a\x00b\r\n\r\n", errMalformed},
		{"CR in value", "GET / HTTP/1.1\r\nHost: h\r\nX: a\rb\r\n\r\n", errMalformed},
		{"non-ASCII value", "GET / HTTP/1.1\r\nHost: h\r\nX: \xff\r\n\r\n", errMalformed},
		{"method not a token", "G(T / HTTP/1.1\r\nHost: h\r\n\r\n", errMalformed},
		{"truncated head (not answered)", "GET / HTTP/1.1\r\nHost: h\r\n", io.ErrUnexpectedEOF},
		{"header block over 8 KiB", big, errHeaderTooLarge},
		{"too many headers", many, errHeaderTooLarge},
		{"request line over 8 KiB", "GET /" + strings.Repeat("a", MaxHeaderBytes) + " HTTP/1.1\r\nHost: h\r\n\r\n", errHeaderTooLarge},
	}
	for _, c := range cases {
		req, err := parse(c.raw)
		switch {
		case c.want == nil && err != nil:
			t.Errorf("%s: refused: %v", c.name, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%s: err %v, want %v (req %+v)", c.name, err, c.want, req)
		}
	}
	req, err := parse(ok)
	if err != nil || req.Method != "GET" || req.Target != "/gomod/x" || req.Host != "127.0.0.1:3128" || req.ContentLength != -1 ||
		req.Close || req.HeadBytes != len(ok) {
		t.Fatalf("parsed %+v %v", req, err)
	}
	if req, _ := parse("GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, Close\r\n\r\n"); req == nil || !req.Close {
		t.Fatalf("Connection: close not seen: %+v", req)
	}
}

// Two requests on one connection are read one after the other: a request without a body leaves nothing behind.
func TestReadRequestPipelined(t *testing.T) {
	br := bufio.NewReader(strings.NewReader("GET /a HTTP/1.1\r\nHost: h\r\n\r\nHEAD /b HTTP/1.1\r\nHost: h\r\n\r\n"))
	a, err := readRequest(br)
	if err != nil || a.Target != "/a" {
		t.Fatalf("first %+v %v", a, err)
	}
	b, err := readRequest(br)
	if err != nil || b.Method != "HEAD" || b.Target != "/b" {
		t.Fatalf("second %+v %v", b, err)
	}
}
