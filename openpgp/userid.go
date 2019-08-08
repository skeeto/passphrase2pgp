package openpgp

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
	packet, err := readPacket(r)
	if err != nil {
		return err
	}
	if packet[0] != 0xc0|13 {
		return errors.New("invalid input")
	}

	u.ID = packet[2:]
	return nil
}
