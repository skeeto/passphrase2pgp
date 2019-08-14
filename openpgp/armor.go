package openpgp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

var ErrInvalidArmor = errors.New("invalid armored data")
var ErrArmorCRC = errors.New("invalid armored checksum")

// Armor returns the ASCII armored version of its input packet. It
// autodetects what kind of armor should be used based on the packet
// header.
func Armor(buf []byte) []byte {
	const (
		pubBeg = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
		pubEnd = "\n-----END PGP PUBLIC KEY BLOCK-----\n"
		secBeg = "-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n"
		secEnd = "\n-----END PGP PRIVATE KEY BLOCK-----\n"
		sigBeg = "-----BEGIN PGP SIGNATURE-----\n\n"
		sigEnd = "\n-----END PGP SIGNATURE-----\n"
	)

	var beg, end string
	switch buf[0] {
	case 0xc0 | 2:
		beg = sigBeg
		end = sigEnd
	case 0xc0 | 5:
		beg = secBeg
		end = secEnd
	case 0xc0 | 6:
		beg = pubBeg
		end = pubEnd
	}

	var asc bytes.Buffer
	asc.WriteString(beg)
	asc.Write(b64encode(buf))
	asc.WriteByte('\n')
	asc.WriteString(b64crc(crc24(buf)))
	asc.WriteString(end)
	return asc.Bytes()
}

func b64encode(in []byte) []byte {
	var out bytes.Buffer
	wrap := &wrapper{&out, 64, 0}
	b64 := base64.NewEncoder(base64.RawStdEncoding.WithPadding('='), wrap)
	b64.Write(in)
	b64.Close()
	return out.Bytes()
}

func b64decode(buf []byte) ([]byte, error) {
	r := bytes.NewReader(buf)
	b64 := base64.NewDecoder(base64.RawStdEncoding.WithPadding('='), r)
	var out bytes.Buffer
	if _, err := io.Copy(&out, b64); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func b64crc(crc int32) string {
	buf := []byte{byte(crc >> 16), byte(crc >> 8), byte(crc)}
	return "=" + string(b64encode(buf))
}

func Dearmor(buf []byte) ([]byte, error) {
	s := bufio.NewScanner(bytes.NewReader(buf))

	// skip opening line
	if !s.Scan() {
		return nil, ErrInvalidArmor
	}
	if !strings.HasPrefix(s.Text(), "-----BEGIN") {
		return nil, ErrInvalidArmor
	}

	// find first blank line
	found := false
	for s.Scan() {
		if s.Text() == "" {
			found = true
			break
		}
	}
	if !found {
		return nil, ErrInvalidArmor
	}

	var b64 bytes.Buffer
	for s.Scan() {
		text := s.Text()
		if strings.HasPrefix(text, "=") {
			break
		}
		b64.WriteString(text)
	}

	check := s.Text()
	if len(check) != 5 {
		return nil, ErrInvalidArmor
	}

	// skip closing line
	if !s.Scan() {
		return nil, ErrInvalidArmor
	}
	if !strings.HasPrefix(s.Text(), "-----END") {
		return nil, ErrInvalidArmor
	}

	raw, err := b64decode(b64.Bytes())
	if err != nil {
		return nil, err
	}
	if check != b64crc(crc24(raw)) {
		return nil, ErrArmorCRC
	}

	return raw, nil
}

// Return CRC-24 checksum for a buffer.
func crc24(buf []byte) int32 {
	const (
		crc24Init = 0x0b704ce
		crc24Poly = 0x1864cfb
	)
	var crc int32 = crc24Init
	for _, b := range buf {
		crc ^= int32(b) << 16
		for i := 0; i < 8; i++ {
			crc <<= 1
			if crc&0x1000000 != 0 {
				crc ^= crc24Poly
			}
		}
	}
	return crc & 0xFFFFFF
}

// wrapper is an io.Writer filter that inserts regular hard line breaks.
type wrapper struct {
	w     io.Writer
	max   int
	count int
}

func (w *wrapper) Write(p []byte) (int, error) {
	for len(p) > 0 {
		if w.count == w.max {
			if _, err := w.w.Write([]byte{10}); err != nil {
				return 0, err
			}
			w.count = 0
		}
		left := w.max - w.count
		var line []byte
		if len(p) > left {
			line = p[:left]
		} else {
			line = p
		}
		p = p[len(line):]
		w.count += len(line)
		_, err := w.w.Write(line)
		if err != nil {
			return 0, err
		}
	}
	return len(p), nil
}
