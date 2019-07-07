package main

import (
	"crypto/sha1"
	"crypto/sha256"
	"flag"
	"math/bits"
	"os"
	"time"

	"golang.org/x/crypto/ed25519"
)

// keylen returns the number of bits in a key, skipping leading zeros.
// This is necessary for MPI encoding.
func keylen(k []byte) int {
	c := len(k) * 8
	for _, b := range k {
		c -= bits.LeadingZeros8(b)
		if c != 0 {
			break
		}
	}
	return c
}

func main() {
	created := flag.Int64("date", 0, "creation date (unix epoch seconds)")
	now := flag.Bool("now", false, "use current time as creation date")
	flag.Parse()

	if *now {
		*created = time.Now().Unix()
	}

	seed := []byte{
		0x1a, 0x8b, 0x1f, 0xf0, 0x5d, 0xed, 0x48, 0xe1,
		0x8b, 0xf5, 0x01, 0x66, 0xc6, 0x64, 0xab, 0x02,
		0x3e, 0xa7, 0x00, 0x03, 0xd7, 0x8d, 0x9e, 0x41,
		0xf5, 0x75, 0x8a, 0x91, 0xd8, 0x50, 0xf8, 0xd2,
	}

	key := ed25519.NewKeyFromSeed(seed)
	sec := key[:32]
	pub := key[32:]
	seclen := keylen(sec) // FIXME: chop leading zeros

	// Secret-Key Packet
	packet := []byte{
		0xc5, // packet header, new format, Secret-Key Packet (5)
		0,    // packet length
		0x04, // packet version, new (4)

		// Public Key
		// creation date
		byte(*created >> 24),
		byte(*created >> 16),
		byte(*created >> 8),
		byte(*created >> 0),
		22, // algorithm, EdDSA
		9,  // OID length
		// OID (1.3.6.1.4.1.11591.15.1)
		0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01,
		// public key length (always 263 bits)
		0x01, 0x07,
		0x40, // MPI prefix
		// public key (32 bytes)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

		// Secret Key
		0, // string-to-key, unencrypted
		// secret key length
		byte(seclen >> 8), byte(seclen >> 0),
		// private key (32 bytes)
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		// checksum
		0, 0,
	}
	packet[1] = byte(len(packet) - 2)
	copy(packet[21:53], pub)
	copy(packet[56:88], sec)
	var checksum uint16
	for _, b := range packet[54:88] {
		checksum += uint16(b)
	}
	packet[88] = byte(checksum >> 8)
	packet[89] = byte(checksum >> 0)
	os.Stdout.Write(packet)

	// User ID Packet
	id := append([]byte{
		0xcd, // packet header, new format, User ID Packet (13)
		0,    // packet length
	}, []byte("Foo Bar <foo.bar@example.com>")...)
	id[1] = byte(len(id) - 2)
	os.Stdout.Write(id)

	// Compute the Key ID
	h := sha1.New()
	h.Write([]byte{0x99, 0, 51}) // "packet" length = 51
	h.Write(packet[2:53])        // public key portion
	keyid := h.Sum(nil)

	// Signature Packet
	sigpacket := []byte{
		0xc2,  // packet header, new format, Signature Packet (2)
		0,     // packet length
		0x04,  // packet version, new (4)
		0x13,  // signature type, Positive certification of a User ID
		22,    // public-key algorithm, EdDSA
		8,     // hash algorithm, SHA-256
		0, 16, // hashed subpacket data length
		// Signature Creation Time subpacket (length=5, type=2)
		5, 2,
		byte(*created >> 24),
		byte(*created >> 16),
		byte(*created >> 8),
		byte(*created >> 0),
		// Issuer subpacket (length=9, type=16)
		9, 16,
		0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, // no unhashed subpacket data
		0, 0, // hash value preview
		0, 0, // MPI bit length
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, // MPI bit length
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	}
	sigpacket[1] = byte(len(sigpacket)) - 2

	// Fill out Issuer subpacket
	copy(sigpacket[16:24], keyid[12:])

	// Compute digest to be signed
	h = sha256.New()
	h.Write([]byte{0x99, 0, 51})
	h.Write(packet[2:53]) // public key portion
	h.Write([]byte{0xb4, 0, 0, 0})
	h.Write(id[1:])
	//h.Write(sigpacket[8:24])
	h.Write(sigpacket[2:24])              // trailer
	h.Write([]byte{4, 0xff, 0, 0, 0, 22}) // final trailer
	sigsum := h.Sum(nil)
	sig := ed25519.Sign(key, sigsum)

	// Fill out hash preview
	sigpacket[26] = sigsum[0]
	sigpacket[27] = sigsum[1]

	// Fill out signature
	r := sig[:32]
	rlen := keylen(r)
	sigpacket[28] = byte(rlen >> 8)
	sigpacket[29] = byte(rlen >> 0)
	copy(sigpacket[30:62], r)
	m := sig[32:]
	mlen := keylen(m)
	sigpacket[62] = byte(mlen >> 8)
	sigpacket[63] = byte(mlen >> 0)
	copy(sigpacket[64:96], m)

	os.Stdout.Write(sigpacket)
}
