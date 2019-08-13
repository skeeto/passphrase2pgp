package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
)

var (
	// pinentryProtocolErr means pinentry responded incorrectly.
	pinentryProtocolErr = errors.New("pinentry protocol error")
	// pinentryCancelErr means the user canceled the input.
	pinentryCancelErr = errors.New("pinentry input canceled")
	// pinentryMismatchErr means the confirmation passphrase did not match.
	pinentryMismatchErr = errors.New("passphrases do not match")
)

// pinentry represents a running, interactive pinentry process used for
// prompting users for passwords.
type pinentry struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Scanner
	err error
}

// Return a handle for a newly initialized pinentry process.
func runPinentry(command string) *pinentry {
	pe := new(pinentry)
	cmd := exec.Command(command)
	in, err := cmd.StdinPipe()
	if err != nil {
		pe.err = err
		return pe
	}
	pe.in = in
	out, err := cmd.StdoutPipe()
	if err != nil {
		pe.err = err
		return pe
	}
	pe.out = bufio.NewScanner(out)
	if err := cmd.Start(); err != nil {
		pe.err = err
		return pe
	}
	pe.wait()
	return pe
}

// Wait for the next "OK" from pinentry, returning any "D" data also sent.
func (p *pinentry) wait() []byte {
	if p.err != nil {
		return nil
	}

	var data []byte
	for p.out.Scan() {
		line := p.out.Text()
		if strings.HasPrefix(line, "ERR ") {
			errstr := line[4:]
			if strings.HasPrefix(errstr, "83886179 ") {
				p.err = pinentryCancelErr
				return data
			}
			p.err = errors.New(errstr)
			return nil
		} else if strings.HasPrefix(line, "OK") {
			return data
		} else if strings.HasPrefix(line, "D ") {
			if data != nil {
				p.err = pinentryProtocolErr
				return nil
			}
			var ok bool
			data, ok = pinentryDecode(p.out.Text()[2:])
			if !ok {
				p.err = pinentryProtocolErr
				return nil
			}
		} else {
			p.err = pinentryProtocolErr
			return data
		}
	}
	if err := p.out.Err(); err != nil {
		p.err = err
	} else {
		p.err = pinentryProtocolErr
	}
	return data
}

// Send message to pinentry and wait for its response with possible data.
// Note: strings must be passed encoded.
func (p *pinentry) Send(args ...string) []byte {
	if p.err != nil {
		return nil
	}

	var buf bytes.Buffer
	for i, arg := range args {
		if i > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(arg)
	}
	buf.WriteByte('\n')
	if _, err := p.in.Write(buf.Bytes()); err != nil {
		p.err = err
		return nil
	}
	return p.wait()
}

// Close the communication channel with pinentry so that it exits.
func (p *pinentry) Close() {
	p.in.Close()
}

// Decode a pinentry data string.
func pinentryDecode(s string) (decoded []byte, valid bool) {
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		b := s[i]
		if b == '%' {
			if len(s[i:]) < 3 {
				return nil, false
			}
			v, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
			if err != nil {
				return nil, false
			}
			buf = append(buf, byte(v))
			i += 3
		} else {
			buf = append(buf, b)
			i++
		}
	}
	return buf, true
}

// Read, confirm, and return a passphrase from the user via pinentry.
func pinentryPassphrase(command, hint string, repeat int) ([]byte, error) {
	pe := runPinentry(command)
	defer pe.Close()
	if hint == "" {
		pe.Send("SETDESC", "passphrase2pgp")
		pe.Send("SETTITLE", "passphrase2pgp")
	} else {
		pe.Send("SETDESC", fmt.Sprintf("passphrase2pgp [%s]", hint))
		pe.Send("SETTITLE", fmt.Sprintf("passphrase2pgp [%s]", hint))
	}
	passphrase := pe.Send("GETPIN")
	for i := 0; i < repeat; i++ {
		again := pe.Send("GETPIN")
		if !bytes.Equal(passphrase, again) {
			return nil, pinentryMismatchErr
		}
	}
	return passphrase, pe.err
}
