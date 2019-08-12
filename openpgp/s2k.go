package openpgp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
)

const (
	// Encoded S2K octet count.
	s2kCount = 0xff // maximum strength
)

func decodeS2K(c byte) int {
	return (16 + int(c&15)) << (uint(c>>4) + 6)
}

// Compute a symmetric protection key via S2K.
func s2k(passphrase, salt []byte, count int) []byte {
	h := sha256.New()
	// Note: This implements S2K as it is actually used in practice by
	// both GnuPG and PGP. The OpenPGP standard (3.7.1.3) is subtly
	// incorrect in its description, and that algorithm is not used by
	// actual implementations.
	// https://dev.gnupg.org/T4676
	full := make([]byte, 8+len(passphrase))
	copy(full[0:], salt)
	copy(full[8:], passphrase)
	iterations := count / len(full)
	for i := 0; i < iterations; i++ {
		h.Write(full)
	}
	tail := count - iterations*len(full)
	h.Write(full[:tail])
	return h.Sum(nil)
}

// Encrypt a secret key along with a SHA-1 "MAC".
func s2kEncrypt(key, iv, seckey []byte) []byte {
	mpikey := mpi(seckey)
	mac := sha1.New()
	mac.Write(mpikey)
	data := mac.Sum(mpikey)
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(data, data)
	return data
}

// Decrypt a secret key and verify its SHA-1 "MAC".
func s2kDecrypt(key, iv, protected []byte) ([]byte, bool) {
	block, _ := aes.NewCipher(key)
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(protected, protected)

	seckey, check := mpiDecode(protected, 32)
	if seckey == nil {
		return nil, false
	}

	mac := sha1.New()
	mac.Write(protected[:len(protected)-20])
	if subtle.ConstantTimeCompare(mac.Sum(nil), check) == 0 {
		return nil, false
	}
	return seckey, true
}
