package parser

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"path"
	"regexp"
	"strings"
)

const (
	maxDepth         = 8
	maxDecompressed  = 32 << 20
	maxArchiveMember = 200
)

type entity struct {
	h         Header
	mediaType string
	params    map[string]string
	filename  string
	body      []byte // transfer-decoded
}

func (e entity) ext() string { return strings.ToLower(path.Ext(e.filename)) }

func parseEntity(raw []byte) entity {
	h, body := ParseHeaderBlock(raw)
	return entityFrom(h, body)
}

func entityFrom(h Header, rawBody []byte) entity {
	e := entity{h: h}
	ct := h.Get("content-type")
	if ct == "" {
		ct = "text/plain"
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = strings.ToLower(strings.TrimSpace(strings.SplitN(ct, ";", 2)[0]))
		params = map[string]string{}
		if m := boundaryRe.FindStringSubmatch(ct); m != nil {
			params["boundary"] = m[1]
		}
	}
	e.mediaType, e.params = mt, params
	if cd := h.Get("content-disposition"); cd != "" {
		if _, p, err := mime.ParseMediaType(cd); err == nil {
			e.filename = p["filename"]
		}
	}
	if e.filename == "" {
		e.filename = params["name"]
	}
	e.filename = decodeWords(e.filename)
	if strings.HasPrefix(mt, "multipart/") {
		e.body = rawBody // multipart bodies must be 7bit/8bit/binary
	} else {
		e.body = decodeCTE(h.Get("content-transfer-encoding"), rawBody)
	}
	return e
}

var boundaryRe = regexp.MustCompile(`(?i)boundary="?([^";]+)"?`)

func decodeCTE(cte string, b []byte) []byte {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		clean := make([]byte, 0, len(b))
		for _, c := range b {
			if c != '\r' && c != '\n' && c != ' ' && c != '\t' {
				clean = append(clean, c)
			}
		}
		out := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
		n, err := base64.StdEncoding.Decode(out, clean)
		if err != nil {
			// Some senders omit padding.
			if n2, err2 := base64.RawStdEncoding.Decode(out, bytes.TrimRight(clean, "=")); err2 == nil {
				return out[:n2]
			}
			return out[:n]
		}
		return out[:n]
	case "quoted-printable":
		out, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(b)))
		if err != nil && len(out) == 0 {
			return b
		}
		return out
	default:
		return b
	}
}

// leaves flattens a MIME tree into its non-multipart parts. message/rfc822
// parts are leaves here - the caller decides whether to descend into them.
func leaves(e entity, depth int, out *[]entity, warn func(string)) {
	if depth > maxDepth {
		warn("MIME nesting too deep; truncated")
		return
	}
	if !strings.HasPrefix(e.mediaType, "multipart/") || e.params["boundary"] == "" {
		*out = append(*out, e)
		return
	}
	mr := multipart.NewReader(bytes.NewReader(e.body), e.params["boundary"])
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			return
		}
		if err != nil {
			warn("multipart: " + err.Error())
			return
		}
		data, err := io.ReadAll(p)
		if err != nil {
			warn("multipart read: " + err.Error())
			return
		}
		h := newHeader()
		for k, vs := range p.Header {
			for _, v := range vs {
				h.Add(k, v)
			}
		}
		leaves(entityFrom(h, data), depth+1, out, warn)
	}
}

// looksLikeMessage reports whether b starts with an RFC 5322 header field.
var headerStartRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9-]{1,75}:[ \t]?\S`)

func looksLikeMessage(b []byte) bool {
	b = bytes.TrimLeft(normalizeNewlines(b[:min(len(b), 4096)]), "\n \t")
	line := b
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		line = b[:i]
	}
	return headerStartRe.Match(line)
}

type archiveFile struct {
	name string
	data []byte
}

// expandArchive unpacks .zip / .gz attachments (capped).
func expandArchive(e entity) ([]archiveFile, bool) {
	mt, ext := e.mediaType, e.ext()
	isZip := bytes.HasPrefix(e.body, []byte("PK\x03\x04"))
	isGzip := bytes.HasPrefix(e.body, []byte{0x1f, 0x8b})
	switch {
	case isZip || mt == "application/zip" || mt == "application/x-zip-compressed" || ext == ".zip":
		zr, err := zip.NewReader(bytes.NewReader(e.body), int64(len(e.body)))
		if err != nil {
			return nil, false
		}
		var out []archiveFile
		var total int64
		for i, f := range zr.File {
			if i >= maxArchiveMember || f.FileInfo().IsDir() {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(rc, maxDecompressed-total))
			rc.Close()
			total += int64(len(b))
			out = append(out, archiveFile{name: f.Name, data: b})
			if total >= maxDecompressed {
				break
			}
		}
		return out, true
	case isGzip || mt == "application/gzip" || mt == "application/x-gzip" || ext == ".gz":
		gr, err := gzip.NewReader(bytes.NewReader(e.body))
		if err != nil {
			return nil, false
		}
		b, _ := io.ReadAll(io.LimitReader(gr, maxDecompressed))
		name := strings.TrimSuffix(e.filename, path.Ext(e.filename))
		if gr.Name != "" {
			name = gr.Name
		}
		return []archiveFile{{name: name, data: b}}, true
	}
	return nil, false
}

var (
	blockTagRe = regexp.MustCompile(`(?i)<\s*(br|/p|/div|/tr|/li|/h[1-6]|/pre)\s*/?>`)
	cellEndRe  = regexp.MustCompile(`(?i)<\s*/t[dh]\s*>`)
	tagRe      = regexp.MustCompile(`(?s)<[^>]*>`)
	styleRe    = regexp.MustCompile(`(?is)<(style|script|head)[^>]*>.*?</(style|script|head)>`)
)

// htmlToText is a crude converter - good enough to find "Field: value" lines
// in reports that were forwarded or rewritten as HTML by a mail client.
func htmlToText(b []byte) []byte {
	s := styleRe.ReplaceAllString(string(b), "")
	s = cellEndRe.ReplaceAllString(s, "\t") // "Label<tab>value" for table-based reports
	s = blockTagRe.ReplaceAllString(s, "\n")
	s = tagRe.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, " ", " ")
	return []byte(s)
}
