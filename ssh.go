package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
)

type pem struct {
	buf   bytes.Buffer
	b64   io.WriteCloser
	stack []io.Writer
	bound  bool
}

func newPEM(bound bool) *pem {
	p := new(pem)
	if bound {
		p.buf.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	}
	encoding := base64.RawStdEncoding.WithPadding('=')
	wrap := &wrapper{&p.buf, 70, 0}
	p.b64 = base64.NewEncoder(encoding, wrap)
	p.stack = append(p.stack, p.b64)
	p.bound = bound
	return p
}

func (p *pem) Close() error {
	if len(p.stack) != 1 {
		panic("PEM Push()/Pop() mismatch")
	}
	p.b64.Close()
	if p.bound {
		p.buf.WriteString("\n-----END OPENSSH PRIVATE KEY-----\n")
	}
	return nil
}

func (p *pem) Push() {
	var buf bytes.Buffer
	p.stack = append(p.stack, &buf)
}

func (p *pem) Pop() {
	top := p.stack[len(p.stack)-1].(*bytes.Buffer)
	p.stack[len(p.stack)-1] = nil
	p.stack = p.stack[:len(p.stack)-1]
	p.Bytes(top.Bytes())
}

func (p *pem) Top() *bytes.Buffer {
	return p.stack[len(p.stack)-1].(*bytes.Buffer)
}

func (p *pem) Output() []byte {
	return p.buf.Bytes()
}

func (p *pem) Write(b []byte) (int, error) {
	return p.stack[len(p.stack)-1].Write(b)
}

func (p *pem) Uint32(v uint32) {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	p.Write(buf[:])
}

func (p *pem) Bytes(b []byte) {
	p.Uint32(uint32(len(b)))
	p.Write(b)
}

func (p *pem) String(str string) {
	p.Bytes([]byte(str))
}

func secSSH(pub, sec, uid, password []byte, rounds uint32) []byte {
	pem := newPEM(true)
	pem.Write([]byte("openssh-key-v1\x00")) // magic

	var pad int
	var check uint32
	var stream cipher.Stream

	if rounds == 0 {
		pem.String("none")  // ciphername
		pem.String("none")  // kdfname
		pem.Bytes([]byte{}) // kdfoptions
		pad = 8
	} else {
		pem.String("aes256-ctr")
		pem.String("bcrypt")

		var buf [20]byte
		if _, err := rand.Read(buf[:]); err != nil {
			panic(err)
		}
		salt := buf[:16]
		check = binary.LittleEndian.Uint32(buf[16:20])

		pem.Push()
		pem.Bytes(salt)
		pem.Uint32(rounds)
		pem.Pop()

		keyiv := bcryptPBKDF(password, salt, 32+16, rounds)
		key := keyiv[:32]
		iv := keyiv[32:]
		block, _ := aes.NewCipher(key)
		stream = cipher.NewCTR(block, iv)
		pad = 16
	}

	pem.Uint32(1) // number of keys

	// Public key
	pem.Push()
	pem.String("ssh-ed25519")
	pem.Bytes(pub)
	pem.Pop()

	// Private key
	pem.Push()
	pem.Uint32(check)
	pem.Uint32(check)
	pem.String("ssh-ed25519")
	pem.Bytes(pub)
	pem.Bytes(append(sec[0:32:32], pub...))
	pem.Bytes(uid)
	top := pem.Top()
	for i := 1; top.Len()%pad != 0; i++ {
		// Pad to block size (despite CTR)
		pem.Write([]byte{byte(i)})
	}
	if rounds > 0 {
		// Encrypt
		buf := top.Bytes()
		stream.XORKeyStream(buf, buf)
	}
	pem.Pop()

	pem.Close()
	return pem.Output()
}

func pubSSH(pub, uid []byte) []byte {
	pem := newPEM(false)
	pem.String("ssh-ed25519")
	pem.Bytes(pub)
	pem.Close()

	out := bytes.NewBufferString("ssh-ed25519 ")
	out.Write(pem.Output())
	out.WriteByte(0x20)
	out.Write(uid)
	out.WriteByte(0x0a)
	return out.Bytes()
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
