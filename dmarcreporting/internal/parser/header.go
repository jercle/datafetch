package parser

import (
	"bytes"
	"mime"
	"strings"
)

// Header is an ordered, case-insensitive multi-map. We use our own lenient
// parser instead of net/textproto because real-world reports contain
// malformed header lines that make the stdlib reject the whole block.
type Header struct {
	order []string // lower-cased keys in first-seen order
	m     map[string][]string
}

func newHeader() Header { return Header{m: map[string][]string{}} }

func (h *Header) Add(k, v string) {
	if h.m == nil {
		h.m = map[string][]string{}
	}
	lk := strings.ToLower(strings.TrimSpace(k))
	if _, ok := h.m[lk]; !ok {
		h.order = append(h.order, lk)
	}
	h.m[lk] = append(h.m[lk], strings.TrimSpace(v))
}

func (h Header) Get(k string) string {
	if v := h.m[strings.ToLower(k)]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func (h Header) Values(k string) []string { return h.m[strings.ToLower(k)] }
func (h Header) Has(k string) bool        { return len(h.m[strings.ToLower(k)]) > 0 }
func (h Header) Len() int                 { return len(h.order) }

// Map returns a copy with original ordering lost (for storage).
func (h Header) Map() map[string][]string {
	out := make(map[string][]string, len(h.m))
	for k, v := range h.m {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// normalizeNewlines converts CRLF / CR to LF.
func normalizeNewlines(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
}

func isFieldName(s string) bool {
	if s == "" || len(s) > 76 {
		return false
	}
	for _, r := range s {
		if r <= 32 || r >= 127 || r == ':' {
			return false
		}
	}
	return true
}

// ParseHeaderBlock parses header fields until the first empty line and
// returns the remaining bytes (the body). Unparseable lines are skipped.
func ParseHeaderBlock(b []byte) (Header, []byte) {
	h := newHeader()
	b = normalizeNewlines(b)
	var lastKey string
	var cur strings.Builder
	flush := func() {
		if lastKey != "" {
			h.Add(lastKey, cur.String())
		}
		lastKey = ""
		cur.Reset()
	}
	for len(b) > 0 {
		var line []byte
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			line, b = b, nil
		}
		if len(bytes.TrimSpace(line)) == 0 {
			if lastKey == "" && h.Len() == 0 {
				continue // tolerate leading blank lines
			}
			flush()
			return h, b
		}
		if line[0] == ' ' || line[0] == '\t' {
			if lastKey != "" {
				cur.WriteByte(' ')
				cur.WriteString(strings.TrimSpace(string(line)))
			}
			continue
		}
		s := string(line)
		i := strings.IndexByte(s, ':')
		if i <= 0 || !isFieldName(strings.TrimSpace(s[:i])) {
			continue // junk line; ignore rather than fail
		}
		flush()
		lastKey = strings.TrimSpace(s[:i])
		cur.WriteString(strings.TrimSpace(s[i+1:]))
	}
	flush()
	return h, nil
}

var wordDecoder = &mime.WordDecoder{}

// decodeWords decodes RFC 2047 encoded-words, returning the input on failure.
func decodeWords(s string) string {
	if !strings.Contains(s, "=?") {
		return s
	}
	if d, err := wordDecoder.DecodeHeader(s); err == nil {
		return d
	}
	return s
}
