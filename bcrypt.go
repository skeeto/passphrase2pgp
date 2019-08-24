package main

import (
	"crypto/sha512"
	"encoding/binary"

	"golang.org/x/crypto/blowfish"
)

// bcryptPBKDF derives a key from a given password and salt using
// OpenBSD's bcrypt_pbkdf() algorithm. It's like PBKDF2 using bcrypt as
// the PRF, except that it's not quite PBKDF2 and the PRF is not quite
// bcrypt.
func bcryptPBKDF(password, salt []byte, keylen int, rounds uint32) []byte {
	blocks := (keylen + 31) / 32
	key := make([]byte, blocks*32)

	h := sha512.New()
	h.Write(password)
	shapwd := h.Sum(nil)

	for i := 0; i < (keylen+31)/32; i++ {
		var bcnt [4]byte
		binary.BigEndian.PutUint32(bcnt[:], uint32(i+1))
		h.Reset()
		h.Write(salt)
		h.Write(bcnt[:])
		shasalt := h.Sum(nil)
		hash := bcryptPRF(shapwd, shasalt)

		var result [32]byte
		copy(result[:], hash)
		for j := int64(1); j < int64(rounds); j++ {
			h.Reset()
			h.Write(hash)
			hash = h.Sum(hash[:0])
			hash = bcryptPRF(shapwd, hash)
			for j := 0; j < len(result); j++ {
				result[j] ^= hash[j]
			}
		}

		// non-linear key transform
		for j := 0; j < 32; j++ {
			key[blocks*j+i] = result[j]
		}
	}
	return key[:keylen]
}

func bcryptPRF(key, salt []byte) []byte {
	c, _ := blowfish.NewSaltedCipher(key, salt)
	for i := 0; i < 64; i++ {
		blowfish.ExpandKey(salt, c)
		blowfish.ExpandKey(key, c)
	}

	hash := []byte("OxychromaticBlowfishSwatDynamite")
	for i := 0; i < 64; i++ {
		for j := 0; j < 32; j += 8 {
			c.Encrypt(hash[j:], hash[j:])
		}
	}

	// byte swap each uint32
	for i := 0; i < 32; i += 4 {
		v := binary.BigEndian.Uint32(hash[i:])
		binary.LittleEndian.PutUint32(hash[i:], v)
	}
	return hash
}
