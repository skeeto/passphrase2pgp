package main

import (
	"bytes"
	"encoding/base64"
	"io"
)

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
	wrap := &wrapper{&asc, 64, 0}
	b64 := base64.NewEncoder(base64.RawStdEncoding.WithPadding('='), wrap)
	b64.Write(buf)
	b64.Close()
	asc.WriteString("\n=")
	b64 = base64.NewEncoder(base64.RawStdEncoding, &asc)
	crc := crc24(buf)
	b64.Write([]byte{byte(crc >> 16), byte(crc >> 8), byte(crc)})
	b64.Close()
	asc.WriteString(end)
	return asc.Bytes()
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
