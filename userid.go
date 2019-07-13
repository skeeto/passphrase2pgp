package main

import (
	"errors"
	"io"
)

// UserID represents a user identity. Implements Bindable.
type UserID struct {
	ID []byte
}

// Packet returns an OpenPGP packet encoding this identity.
func (u *UserID) Packet() []byte {
	packet := make([]byte, len(u.ID)+2)
	packet[0] = 0xc0 | 13       // packet header, User ID Packet (13)
	packet[1] = byte(len(u.ID)) // packet length
	copy(packet[2:], u.ID)
	return packet
}

// Load from OpenPGP input (Packet() output).
func (u *UserID) Load(r io.Reader) (err error) {
	invalid := errors.New("invalid input")
	defer func() {
		if recover() != nil {
			err = invalid
		}
	}()

	var buf [257]byte
	if _, err := r.Read(buf[:2]); err != nil {
		return err
	}
	if buf[0] != 0xc0|13 {
		return invalid
	}
	packet := buf[:2+buf[1]]
	if _, err := r.Read(packet[2:]); err != nil {
		return err
	}

	u.ID = packet[2:]
	return nil
}

func (u *UserID) SignType() byte {
	return 0x13
}

func (u *UserID) SignData() []byte {
	prefix := []byte{0xb4, 0, 0, 0}
	packet := u.Packet()[1:]
	return append(prefix, packet...)
}
