package openpgp

import (
	"encoding/binary"
	"errors"
	"io"
	"math/bits"
)

var InvalidPacketErr = errors.New("invalid OpenPGP data")

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
	} else if 2+bytes > len(buf) {
		return nil, nil
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

// Packet represents a packet container.
type Packet struct {
	Tag    byte
	HdrLen int
	Body   []byte
}

// ParsePacket returns the header of next packet in the buffer and the
// bytes following the packet.
func ParsePacket(buf []byte) (Packet, []byte, error) {
	var p Packet

	if len(buf) < 2 || buf[0]&0x80 == 0 {
		return p, nil, InvalidPacketErr
	}

	var bodyLen int
	if buf[0]&0x40 != 0 {
		// New format
		p.Tag = buf[0] & 0x3f

		n0 := int(buf[1])
		if n0 < 192 {
			p.HdrLen = 2
			bodyLen = n0
		} else if n0 == 0xff {
			p.HdrLen = 6
			if len(buf) < p.HdrLen {
				return p, nil, InvalidPacketErr
			}
			bodyLen = int(binary.BigEndian.Uint32(buf[2:]))
		} else {
			p.HdrLen = 3
			if len(buf) < p.HdrLen {
				return p, nil, InvalidPacketErr
			}
			n1 := int(buf[2])
			bodyLen = ((n0 - 192) << 8) + n1 + 192
		}

	} else {
		// Old format
		p.Tag = (buf[0] >> 2) & 0x0f

		switch buf[0] & 0x03 {
		case 0:
			p.HdrLen = 2
		case 1:
			p.HdrLen = 3
		case 2:
			p.HdrLen = 5
		case 3:
			return p, nil, InvalidPacketErr // don't bother
		}

		if len(buf) < p.HdrLen {
			return p, nil, InvalidPacketErr
		}
		switch p.HdrLen {
		case 2:
			bodyLen = int(buf[1])
		case 3:
			bodyLen = int(binary.BigEndian.Uint16(buf[1:]))
		case 5:
			bodyLen = int(binary.BigEndian.Uint32(buf[1:]))
		}
	}

	if len(buf) < p.HdrLen+bodyLen {
		return p, nil, InvalidPacketErr
	}
	p.Body = buf[p.HdrLen : p.HdrLen+bodyLen]
	return p, buf[p.HdrLen+bodyLen:], nil
}

func (p *Packet) Encode() []byte {
	n := len(p.Body)
	if n <= 191 {
		packet := make([]byte, 2+n)
		packet[0] = 0xc0 | p.Tag
		packet[1] = byte(n)
		return append(packet[:2], p.Body...)
	} else if n <= 8383 {
		packet := make([]byte, 3+n)
		packet[0] = 0xc0 | p.Tag
		packet[1] = byte((n-192)>>8) + 192
		packet[2] = byte(n - 192)
		return append(packet[:3], p.Body...)
	} else {
		packet := make([]byte, 6+n)
		packet[0] = 0xc0 | p.Tag
		packet[1] = 0xff
		binary.BigEndian.PutUint32(packet[2:], uint32(n))
		return append(packet[:6], p.Body...)
	}
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

// Return a 4-byte buffer encoding a uint32.
func marshal32be(v uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, v)
	return data
}
