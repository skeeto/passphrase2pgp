package openpgp

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"time"

	"golang.org/x/crypto/ed25519"
)

const (
	// SignKeyPubLen is the size of the public part of an OpenPGP packet.
	SignKeyPubLen = 53
	signKeySecLen = 3 + 32 + 2
)

// SignKey represents an Ed25519 sign key (EdDSA).
type SignKey struct {
	Key     ed25519.PrivateKey
	created int64
	expires int64
	packet  []byte
}

// Seed sets the 32-byte seed for a sign key.
func (k *SignKey) Seed(seed []byte) {
	k.Key = ed25519.NewKeyFromSeed(seed)
	k.packet = nil
}

// Created returns the key's creation date in unix epoch seconds.
func (k *SignKey) Created() int64 {
	return k.created
}

// SetCreated sets the creation date in unix epoch seconds.
func (k *SignKey) SetCreated(time int64) {
	k.created = time
	k.packet = nil
}

// Expired returns the key's expiration time in unix epoch seconds. A
// value of zero means the key doesn't expire.
func (k *EncryptKey) Expires() int64 {
	return k.expires
}

// SetExpire returns the key's expiration time in unix epoch seconds. A
// value of zero means the key doesn't expire.
func (k *EncryptKey) SetExpires(time int64) {
	k.expires = time
}

// Load entire key from OpenPGP input (Packet() output).
func (k *SignKey) Load(r io.Reader) (err error) {
	invalid := errors.New("invalid input")
	defer func() {
		if recover() != nil {
			err = invalid
		}
	}()

	// Read entire packet from input
	packet, err := readPacket(r)
	if err != nil {
		return err
	}
	if packet[0] != 0xc0|5 {
		return invalid
	}

	// Check various static bytes
	if packet[2] != 0x04 || !bytes.Equal(packet[7:21], []byte{
		22, 9,
		0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
		0x01, 0x07, 0x40,
	}) || packet[53] != 0 {
		return invalid
	}

	// Extract the fields we care about
	pubkey := packet[21:53]
	seckey, tail := mpiDecode(packet[54:], 32)
	created := int64(binary.BigEndian.Uint32(packet[3:]))
	if len(tail) != 2 {
		return invalid
	}

	k.SetCreated(created)
	k.Seed(seckey)
	if !bytes.Equal(k.Pubkey(), pubkey) {
		return invalid
	}
	return nil
}

// Seckey returns the public key part of a sign key.
func (k *SignKey) Seckey() []byte {
	return k.Key[:32]
}

// Pubkey returns the public key part of a sign key.
func (k *SignKey) Pubkey() []byte {
	return k.Key[32:]
}

// Packet returns an OpenPGP packet for a sign key.
func (k *SignKey) Packet() []byte {
	be := binary.BigEndian

	if k.packet != nil {
		return k.packet
	}

	packet := make([]byte, SignKeyPubLen+1, SignKeyPubLen+signKeySecLen)
	packet[0] = 0xc0 | 5 // packet header, Secret-Key Packet (5)
	packet[2] = 0x04     // packet version, new (4)

	// Public Key
	be.PutUint32(packet[3:], uint32(k.created)) // creation date
	packet[7] = 22                              // algorithm, EdDSA
	packet[8] = 9                               // OID length
	// OID (1.3.6.1.4.1.11591.15.1)
	oid := []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01}
	copy(packet[9:], oid)
	be.PutUint16(packet[18:], 263)  // public key length (always 263 bits)
	packet[20] = 0x40               // MPI prefix
	copy(packet[21:53], k.Pubkey()) // public key (32 bytes)

	// Secret Key
	packet[53] = 0 // string-to-key, unencrypted
	mpikey := mpi(k.Seckey())
	packet = append(packet, mpikey...)
	// Append checksum
	packet = packet[:len(packet)+2]
	be.PutUint16(packet[len(packet)-2:], checksum(mpikey))

	packet[1] = byte(len(packet) - 2) // packet length
	k.packet = packet
	return packet
}

// PubPacket returns a public key packet for this key.
func (k *SignKey) PubPacket() []byte {
	packet := make([]byte, SignKeyPubLen)
	packet[0] = 0xc0 | 6 // packet header, Public-Key packet (6)
	packet[1] = SignKeyPubLen - 2
	copy(packet[2:], k.Packet()[2:])
	return packet
}

// KeyID returns the Key ID for a sign key.
func (k *SignKey) KeyID() []byte {
	h := sha1.New()
	h.Write([]byte{0x99, 0, 51})         // "packet" length = 51
	h.Write(k.Packet()[2:SignKeyPubLen]) // public key portion
	return h.Sum(nil)
}

type Subpacket struct {
	Type byte
	Data []byte
}

// Bindable represents something that can be signed by a sign key.
type Bindable interface {
	// SignType returns the signature type ID needed for this object.
	SignType() byte

	// SignPackets returns the hashed subpackets for this key.
	Subpackets() []Subpacket

	// SignData returns the data to be concatenated with other hash input.
	SignData() []byte
}

// Bind a Bindable object to this key using an OpenPGP packet.
func (k *SignKey) Bind(s Bindable, created int64) []byte {
	var subpackets []Subpacket
	sigtype := s.SignType()

	packet := make([]byte, 8, 257)
	packet[0] = 0xc0 | 2 // packet header, new format, Signature Packet (2)
	packet[2] = 0x04     // packet version, new (4)
	packet[3] = sigtype  // signature type
	packet[4] = 22       // public-key algorithm, EdDSA
	packet[5] = 8        // hash algorithm, SHA-256

	// Signature Creation Time subpacket (type=2)
	sigCreated := Subpacket{
		Type: 2,
		Data: marshal32be(uint32(created)),
	}
	subpackets = append(subpackets, sigCreated)

	// Issuer subpacket (type=16)
	issuer := Subpacket{
		Type: 16,
		Data: k.KeyID()[12:20],
	}
	subpackets = append(subpackets, issuer)
	// An Issuer Fingerprint subpacket is unnecessary here because this
	// is a self-signature, and so even the Issuer subpacket is already
	// redundant. The recipient already knows which key we're talking
	// about. Technically the Issuer subpacket is optional, but GnuPG
	// will not import a key without it.

	// Self-signature for this very key?
	if sigtype == 0x13 {
		// Key Flags subpacket (type=27) [sign and certify]
		// This is necessary since some implementations (GitHub) treat
		// all flags as if they were zero if not present.
		flags := Subpacket{
			Type: 27,
			Data: []byte{0x03},
		}
		subpackets = append(subpackets, flags)

		if k.expires != 0 {
			// Key Expiration Time subpacket (type=9)
			expires := Subpacket{
				Type: 9,
				Data: marshal32be(uint32(k.expires - k.created)),
			}
			subpackets = append(subpackets, expires)
		}
	}

	subpackets = append(subpackets, s.Subpackets()...)
	for _, subpacket := range subpackets {
		packet = append(packet, byte(len(subpacket.Data)+1))
		packet = append(packet, subpacket.Type)
		packet = append(packet, subpacket.Data...)
	}

	// Hashed subpacket data length
	hashedLen := uint16(len(packet) - 8)
	binary.BigEndian.PutUint16(packet[6:8], hashedLen)

	// Unhashed subpacket data (none)
	packet = packet[:len(packet)+2]
	binary.BigEndian.PutUint16(packet[len(packet)-2:], 0)

	// Compute digest to be signed
	h := sha256.New()

	// Write public key
	h.Write([]byte{0x99, 0, 51})
	h.Write(k.PubPacket()[2:])

	// Write target of Bind()
	h.Write(s.SignData())

	// Write hash trailers
	h.Write(packet[2 : hashedLen+8])                       // trailer
	h.Write([]byte{4, 0xff, 0, 0, 0, byte(hashedLen + 6)}) // final trailer

	// Compute hash and sign
	sigsum := h.Sum(nil)
	sig := ed25519.Sign(k.Key, sigsum)

	// hash preview
	packet = append(packet, sigsum[:2]...)

	// signature
	r := sig[:32]
	packet = append(packet, mpi(r)...)
	m := sig[32:]
	packet = append(packet, mpi(m)...)

	// Finalize
	packet[1] = byte(len(packet)) - 2 // packet length
	return packet
}

// Sign binary data with this key using an OpenPGP signature packet.
func (k *SignKey) Sign(src io.Reader) ([]byte, error) {
	const sigtype = 0x00 // binary document
	// Compute digest to be signed
	h := sha256.New()
	if _, err := io.Copy(h, src); err != nil {
		return nil, err
	}
	return k.sign(h, sigtype), nil
}

// Clearsign returns a new cleartext stream signer. Data from the
// given reader will be cleartext-signed and wrtten into the returned
// reader. The returned reader must either be read completely or closed.
func (k *SignKey) Clearsign(src io.Reader) io.ReadCloser {
	const sigtype = 0x01 // text document
	r, w := io.Pipe()
	go func() {
		open := []byte("-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\n")
		crlf := []byte("\r\n")
		tmp := make([]byte, 128)
		if _, err := w.Write(open); err != nil {
			return
		}
		s := bufio.NewScanner(src)
		h := sha256.New()
		first := true
		for s.Scan() {
			line := s.Bytes()

			// Remove trailing whitespace
			for i := len(line) - 1; i >= 0; i-- {
				if line[i] == 0x20 || line[i] == 0x09 {
					line = line[:i]
				} else {
					break
				}
			}

			// Append to hash
			if !first {
				h.Write(crlf)
			}
			first = false
			h.Write(line)

			// Pass through dash-encoded
			if len(line) > 0 && line[0] == 0x2d {
				tmp = tmp[:2]
				tmp[0] = 0x2d
				tmp[1] = 0x20
			} else {
				tmp = tmp[:0]
			}
			tmp = append(tmp, line...)
			tmp = append(tmp, 0x0a)
			if _, err := w.Write(tmp); err != nil {
				return
			}
		}
		if err := s.Err(); err != nil {
			w.CloseWithError(err)
		}
		sig := Armor(k.sign(h, sigtype))
		if _, err := w.Write(sig); err != nil {
			return
		}
		w.Close()
	}()
	return r
}

// Generic signature framework for both binary and text signatures.
func (k *SignKey) sign(h hash.Hash, sigtype byte) []byte {
	const (
		hashedLen = 39
		fixedLen  = 51
	)
	be := binary.BigEndian

	packet := make([]byte, fixedLen, fixedLen+66)
	packet[0] = 0xc0 | 2 // packet header, new format, Signature Packet (2)
	packet[2] = 0x04     // packet version, new (4)
	packet[3] = sigtype  // signature type
	packet[4] = 22       // public-key algorithm, EdDSA
	packet[5] = 8        // hash algorithm, SHA-256
	be.PutUint16(packet[6:8], hashedLen)

	// Signature Creation Time subpacket (length=5, type=2)
	packet[8] = 5
	packet[9] = 2
	created := time.Now().Unix()
	be.PutUint32(packet[10:14], uint32(created))

	// Issuer subpacket (length=9, type=16)
	packet[14] = 9
	packet[15] = 16
	keyid := k.KeyID()
	copy(packet[16:24], keyid[12:20])

	// Issuer Fingerprint subpacket (length=22, type=33)
	packet[24] = 22
	packet[25] = 33
	packet[26] = 04 // fingerprint version
	copy(packet[27:47], keyid)

	// Unhashed subpacket data (none)
	be.PutUint16(packet[47:49], 0)

	// Append trailers to the end of the digest input
	h.Write(packet[2 : hashedLen+8])                 // trailer
	h.Write([]byte{4, 0xff, 0, 0, 0, hashedLen + 6}) // final trailer
	sigsum := h.Sum(nil)
	sig := ed25519.Sign(k.Key, sigsum)

	// hash preview
	copy(packet[49:51], sigsum[:2])

	// signature
	r := sig[:32]
	packet = append(packet, mpi(r)...)
	m := sig[32:]
	packet = append(packet, mpi(m)...)

	// Finalize
	packet[1] = byte(len(packet)) - 2 // packet length
	return packet
}
