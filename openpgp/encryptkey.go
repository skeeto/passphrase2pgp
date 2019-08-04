package openpgp

import (
	"encoding/binary"

	"golang.org/x/crypto/curve25519"
)

const (
	// EncryptKeyPubLen is the size of the public part of an OpenPGP packet.
	EncryptKeyPubLen = 58
)

// EncryptKey represents an X25519 Diffie-Hellman key (ECDH). Implements
// Bindable.
type EncryptKey struct {
	Key     []byte
	created int64
	expires int64
	packet  []byte
}

// Seed sets the 32-byte seed for a sign key.
func (k *EncryptKey) Seed(seed []byte) {
	var pubkey [32]byte
	var seckey [32]byte
	copy(seckey[:], seed)
	seckey[0] &= 248
	seckey[31] &= 127
	seckey[31] |= 64
	curve25519.ScalarBaseMult(&pubkey, &seckey)
	k.Key = append(seckey[:], pubkey[:]...)
	k.packet = nil
}

// Created returns the key's creation date in unix epoch seconds.
func (k *EncryptKey) Created() int64 {
	return k.created
}

// SetCreated sets the creation date in unix epoch seconds.
func (k *EncryptKey) SetCreated(time int64) {
	k.created = time
	k.packet = nil
}

// Expired returns the key's expiration time in unix epoch seconds. A
// value of zero means the key doesn't expire.
func (k *SignKey) Expires() int64 {
	return k.expires
}

// SetExpire returns the key's expiration time in unix epoch seconds. A
// value of zero means the key doesn't expire.
func (k *SignKey) SetExpires(time int64) {
	k.expires = time
}

// Seckey returns the secret key portion of this key.
func (k *EncryptKey) Seckey() []byte {
	return k.Key[:32]
}

// Pubkey returns the public key portion of this key.
func (k *EncryptKey) Pubkey() []byte {
	return k.Key[32:]
}

// Packet returns the OpenPGP packet encoding this key.
func (k *EncryptKey) Packet() []byte {
	const encryptKeySecLen = 3 + 32 + 2
	total := EncryptKeyPubLen + encryptKeySecLen
	be := binary.BigEndian

	if k.packet != nil {
		return k.packet
	}

	packet := make([]byte, EncryptKeyPubLen+1, total)
	packet[0] = 0xc0 | 7 // packet header, Secret-Subkey Packet (7)
	packet[2] = 0x04     // packet version, new (4)

	// Public Key
	be.PutUint32(packet[3:7], uint32(k.created)) // creation date
	packet[7] = 18                               // algorithm, Elliptic Curve
	packet[8] = 10                               // OID length
	// OID (1.3.6.1.4.1.3029.1.5.1)
	oid := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
	copy(packet[9:19], oid)
	be.PutUint16(packet[19:21], 263) // public key length (always 263 bits)
	packet[21] = 0x40                // MPI prefix
	copy(packet[22:54], k.Pubkey())
	// KDF parameters
	packet[54] = 3    // length
	packet[55] = 0x01 // reserved (1)
	packet[56] = 0x08 // SHA-256
	packet[57] = 0x07 // AES-128? (spec is incorrect)

	// Secret Key
	packet[58] = 0 // string-to-key, unencrypted
	// append MPI-encoded key
	mpikey := mpi(reverse(k.Seckey()))
	packet = append(packet, mpikey...)
	// Append checksum
	packet = packet[:len(packet)+2]
	be.PutUint16(packet[len(packet)-2:], checksum(mpikey))

	packet[1] = byte(len(packet) - 2) // packet length
	k.packet = packet
	return packet
}

// PubPacket returns an OpenPGP public key packet for this key.
func (k *EncryptKey) PubPacket() []byte {
	packet := make([]byte, EncryptKeyPubLen)
	packet[0] = 0xc0 | 14 // packet header, Public-Subkey packet (14)
	packet[1] = EncryptKeyPubLen - 2
	copy(packet[2:], k.Packet()[2:])
	return packet
}

func (k *EncryptKey) SignType() byte {
	return 0x18
}

func (k *EncryptKey) Subpackets() []Subpacket {
	subpackets := []Subpacket{
		// Key Flags subpacket (encrypt)
		{Type: 27, Data: []byte{0x0c}},
		// Key Expiration Time packet
		{Type: 9, Data: marshal32be(uint32(k.expires - k.created))},
	}
	if k.expires != 0 {
		return subpackets
	} else {
		return subpackets[:1]
	}
}

func (k *EncryptKey) SignData() []byte {
	prefix := []byte{0x99, 0, 56}
	packet := k.PubPacket()[2:]
	return append(prefix, packet...)
}

// Returns a reversed copy of its input.
func reverse(b []byte) []byte {
	c := make([]byte, len(b))
	for i, v := range b {
		c[len(c)-i-1] = v
	}
	return c
}
