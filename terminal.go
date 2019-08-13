package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/crypto/ssh/terminal"
)

// Read, confirm, and return a passphrase from the user via terminal.
func terminalPassphrase(hint string, repeat int) ([]byte, error) {
	fd := int(syscall.Stdin)
	var out io.Writer = os.Stderr
	if !terminal.IsTerminal(fd) {
		tty, err := os.Create("/dev/tty") // O_RDWR
		if err != nil {
			fatal("failed to open /dev/tty")
		}
		defer tty.Close()
		fd = int(tty.Fd())
		out = tty
	}

	var prompt, promptRepeat string
	if hint == "" {
		prompt = "passphrase: "
		promptRepeat = "passphrase (repeat): "
	} else {
		prompt = fmt.Sprintf("passphrase [%s]: ", hint)
		promptRepeat = fmt.Sprintf("passphrase [%s] (repeat): ", hint)
	}

	tail := []byte("\n")
	out.Write([]byte(prompt))
	passphrase, err := terminal.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	if passphrase == nil {
		passphrase = make([]byte, 0)
	}
	out.Write(tail)
	for i := 0; i < repeat; i++ {
		out.Write([]byte(promptRepeat))
		again, err := terminal.ReadPassword(fd)
		if err != nil {
			return nil, err
		}
		out.Write(tail)
		if !bytes.Equal(again, passphrase) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return passphrase, nil
}
