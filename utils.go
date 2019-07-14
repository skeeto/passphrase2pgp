package main

import (
	"encoding/binary"
	"io"
	"math/bits"
)

// Returns data encoded as an OpenPGP multiprecision integer.
func mpi(data []byte) []byte {
	// Chop off leading zeros
	for len(data) > 0 && data[0] == 0 {
		data = data[1:]
	}
	// Zero-length is a special case (should never actually happen)
	if len(data) == 0 {
		return []byte{0, 0}
	}
	c := len(data)*8 - bits.LeadingZeros8(data[0])
	mpi := []byte{byte(c >> 8), byte(c >> 0)}
	return append(mpi, data...)
}

// Returns the decoded MPI integer and the remaining buffer.
func mpiDecode(buf []byte, desired int) (i, remain []byte) {
	bits := int(binary.BigEndian.Uint16(buf))
	bytes := (bits + 7) / 8
	if bytes < desired {
		i = make([]byte, desired)
		copy(i[desired-bytes:], buf[2:2+bytes])
	} else {
		i = buf[2 : 2+bytes]
	}
	remain = buf[2+bytes:]
	return
}

// Returns the checksum for an MPI-encoded key.
func checksum(mpi []byte) uint16 {
	var checksum uint16
	for _, b := range mpi {
		checksum += uint16(b)
	}
	return checksum
}

// Returns the entire next packet from the input. Packets are always at
// least two bytes long.
func readPacket(r io.Reader) ([]byte, error) {
	var buf [257]byte
	if _, err := r.Read(buf[:2]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	packet := buf[:2+buf[1]]
	if _, err := r.Read(packet[2:]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return packet, nil
}
