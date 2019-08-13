package openpgp

import (
	"bytes"
	"crypto/rand"
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
}

// Created returns the key's creation date in unix epoch seconds.
func (k *EncryptKey) Created() int64 {
	return k.created
}

// SetCreated sets the creation date in unix epoch seconds.
func (k *EncryptKey) SetCreated(time int64) {
	k.created = time
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

// PubPacket returns an OpenPGP public key packet for this key.
func (k *EncryptKey) PubPacket() []byte {
	packet := make([]byte, EncryptKeyPubLen, 256)
	packet[0] = 0xc0 | 14 // packet header, Public-Subkey packet (14)
	packet[2] = 0x04      // packet version, new (4)

	binary.BigEndian.PutUint32(packet[3:7], uint32(k.created))
	packet[7] = 18 // algorithm, Elliptic Curve
	packet[8] = 10 // OID length
	// OID (1.3.6.1.4.1.3029.1.5.1)
	oid := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}
	copy(packet[9:19], oid)

	// public key length (always 263 bits)
	binary.BigEndian.PutUint16(packet[19:21], 263)
	packet[21] = 0x40 // MPI prefix
	copy(packet[22:54], k.Pubkey())

	// KDF parameters
	packet[54] = 3 // length
	packet[55] = 1 // reserved (1)
	packet[56] = 8 // SHA-256
	packet[57] = 9 // AES-256

	packet[1] = byte(len(packet) - 2) // packet length
	return packet
}

// Packet returns the OpenPGP packet encoding this key.
func (k *EncryptKey) Packet() []byte {
	packet := k.PubPacket()
	packet[0] = 0xc0 | 7 // packet header, Secret-Subkey Packet (7)

	packet = append(packet, 0) // string-to-key, unencrypted
	mpikey := mpi(reverse(k.Seckey()))
	packet = append(packet, mpikey...)
	packet = packet[:len(packet)+2]
	binary.BigEndian.PutUint16(packet[len(packet)-2:], checksum(mpikey))

	packet[1] = byte(len(packet) - 2) // packet length
	return packet
}

// EncPacket returns a protected secret key packet.
func (k *EncryptKey) EncPacket(passphrase []byte) []byte {
	var saltIV [24]byte
	if _, err := rand.Read(saltIV[:]); err != nil {
		panic(err) // should never happen
	}
	salt := saltIV[:8]
	iv := saltIV[8:]
	key := s2k(passphrase, salt, decodeS2K(s2kCount))
	protected := s2kEncrypt(key, iv, reverse(k.Seckey()))

	packet := k.PubPacket()[:EncryptKeyPubLen+4]
	packet[0] = 0xc0 | 7 // packet header, Secret-Subkey Packet (7)

	packet[58] = 254 // encrypted with S2K
	packet[59] = 9   // AES-256
	packet[60] = 3   // Iterated and Salted S2K
	packet[61] = 8   // SHA-256
	packet = append(packet, salt...)
	packet = append(packet, s2kCount)
	packet = append(packet, iv...)
	packet = append(packet, protected...)

	packet[1] = byte(len(packet) - 2) // packet length
	return packet
}

// Load key material from packet body. If the error is DecryptKeyErr,
// then either the passphrase was nil or the passphrase is wrong. To use
// an empty passphrase, pass an empty but non-nil passphrase.
func (k *EncryptKey) Load(packet Packet, passphrase []byte) (err error) {
	defer func() {
		if recover() != nil {
			err = InvalidPacketErr
		}
	}()

	switch packet.Tag {
	case 7:
		// Ok
	case 14:
		// TODO: Support loading public key packets
		return UnsupportedPacketErr
	default:
		// Wrong packet type
		return InvalidPacketErr
	}

	// Check various static bytes
	body := packet.Body
	if body[0] != 0x04 || !bytes.Equal(body[5:17], []byte{
		18, 10,
		0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01,
	}) {
		return UnsupportedPacketErr
	}

	pubkey := body[20:52]
	created := int64(binary.BigEndian.Uint32(body[1:]))
	k.SetCreated(created)

	// KDF parameters
	secbody := body[53+body[52]:] // skip KDF parameters

	var seckey []byte
	if secbody[0] == 0 {
		// Unencrypted
		var tail []byte
		seckey, tail = mpiDecode(secbody[1:], 32)
		if len(tail) != 2 {
			return InvalidPacketErr
		}
	} else if secbody[0] == 254 {
		// Encrypted
		if passphrase == nil {
			return DecryptKeyErr // missing passphrase
		}

		if secbody[1] != 9 || // AES-256
			secbody[2] != 3 || // Iterated and Salted S2K
			secbody[3] != 8 { // SHA-256
			return UnsupportedPacketErr
		}
		salt := secbody[4:12]
		count := decodeS2K(secbody[12])
		iv := secbody[13:29]
		data := secbody[29:]
		key := s2k(passphrase, salt, count)
		var ok bool
		seckey, ok = s2kDecrypt(key, iv, data)
		if !ok {
			return DecryptKeyErr
		}
	}

	k.Seed(reverse(seckey))
	if !bytes.Equal(k.Pubkey(), pubkey) {
		return InvalidPacketErr
	}
	return nil
}

// Returns a reversed copy of its input.
func reverse(b []byte) []byte {
	c := make([]byte, len(b))
	for i, v := range b {
		c[len(c)-i-1] = v
	}
	return c
}
