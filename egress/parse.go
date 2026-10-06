package egress

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
)

// Parser bounds (egress.md §3).
const (
	MaxHeaderBytes = 8 << 10
	maxHeaders     = 64
)

var (
	errHeaderTooLarge = errors.New("header block exceeds 8 KiB")
	errMalformed      = errors.New("malformed request")
)

// Request is a parsed HTTP/1.1 request head. The service accepts no request body.
type Request struct {
	Method, Target string
	Host           string
	ContentLength  int64 // -1 when absent
	Close          bool  // Connection: close
	HeadBytes      int
}

// readRequest reads one request head from br, strictly: CRLF line endings only, at most 8 KiB, exactly
// HTTP/1.1, token methods and header names, no obs-fold, no control or non-ASCII bytes, exactly one Host,
// and none of the smuggling forms (a duplicate Content-Length, any Transfer-Encoding).
// It returns errHeaderTooLarge, errMalformed (wrapped with the reason), io.ErrUnexpectedEOF for a head cut short,
// or the read error (such as the header timeout). Only the first two are answered.
func readRequest(br *bufio.Reader) (*Request, error) {
	n := 0
	line := func() ([]byte, error) {
		var buf []byte
		for {
			b, err := br.ReadSlice('\n')
			n += len(b)
			if n > MaxHeaderBytes {
				return nil, errHeaderTooLarge
			}
			buf = append(buf, b...)
			if err == bufio.ErrBufferFull {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !bytes.HasSuffix(buf, []byte("\r\n")) {
				return nil, malformed("bare LF")
			}
			return buf[:len(buf)-2], nil
		}
	}
	first, err := line()
	if err != nil {
		return nil, err
	}
	req := &Request{ContentLength: -1}
	method, rest, ok1 := strings.Cut(string(first), " ")
	target, proto, ok2 := strings.Cut(rest, " ")
	switch {
	case !ok1 || !ok2:
		return nil, malformed("request line")
	case !isToken(method):
		return nil, malformed("method")
	case target == "" || !isVisible(target):
		return nil, malformed("request target")
	case proto != "HTTP/1.1":
		return nil, malformed("version")
	}
	req.Method, req.Target = method, target
	hosts, lengths, count := 0, 0, 0
	for {
		l, err := line()
		if err != nil {
			if err == io.EOF {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if len(l) == 0 {
			break
		}
		if count++; count > maxHeaders {
			return nil, errHeaderTooLarge
		}
		if l[0] == ' ' || l[0] == '\t' {
			return nil, malformed("obs-fold")
		}
		name, value, ok := strings.Cut(string(l), ":")
		if !ok || !isToken(name) {
			return nil, malformed("header name")
		}
		value = strings.Trim(value, " \t")
		if !isFieldValue(value) {
			return nil, malformed("header value")
		}
		switch strings.ToLower(name) {
		case "host":
			hosts++
			req.Host = value
		case "content-length":
			lengths++
			v, err := strconv.ParseInt(value, 10, 64)
			if err != nil || v < 0 || value != strconv.FormatInt(v, 10) {
				return nil, malformed("content-length")
			}
			req.ContentLength = v
		case "transfer-encoding":
			return nil, malformed("transfer-encoding")
		case "connection":
			for _, t := range strings.Split(value, ",") {
				if strings.EqualFold(strings.TrimSpace(t), "close") {
					req.Close = true
				}
			}
		}
	}
	switch {
	case hosts != 1:
		return nil, malformed("exactly one Host is required")
	case lengths > 1:
		return nil, malformed("duplicate content-length")
	}
	req.HeadBytes = n
	return req, nil
}

type malformedError string

func (e malformedError) Error() string { return errMalformed.Error() + ": " + string(e) }
func (e malformedError) Unwrap() error { return errMalformed }

func malformed(why string) error { return malformedError(why) }

// isToken reports whether s is an RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0 {
			continue
		}
		return false
	}
	return true
}

// isVisible reports whether s holds only visible ASCII (no space, control or non-ASCII byte).
func isVisible(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] <= ' ' || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// isFieldValue reports whether s holds only visible ASCII, spaces and tabs.
func isFieldValue(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < ' ' && c != '\t') || c >= 0x7f {
			return false
		}
	}
	return true
}
