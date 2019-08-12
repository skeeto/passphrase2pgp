package openpgp

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

// Load from packet.
func (u *UserID) Load(packet Packet) (err error) {
	if packet.Tag != 13 {
		return InvalidPacketErr
	}
	u.ID = packet.Body
	return nil
}
