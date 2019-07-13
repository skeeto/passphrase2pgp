package main

import (
	"bytes"
	"testing"
)

func TestMpi(t *testing.T) {
	table := []struct {
		input, want []byte
	}{
		{[]byte{0x80, 0, 0, 0}, []byte{0, 32, 0x80, 0, 0, 0}},
		{[]byte{1, 0, 0, 0}, []byte{0, 25, 1, 0, 0, 0}},
		{[]byte{0, 0, 0, 1}, []byte{0, 1, 1}},
		{[]byte{0, 0, 1, 0}, []byte{0, 9, 1, 0}},
		{[]byte{0x0f, 0xde, 0xad, 0xbe, 0xef},
			[]byte{0, 36, 0x0f, 0xde, 0xad, 0xbe, 0xef}},
	}

	for _, row := range table {
		got := mpi(row.input)
		if !bytes.Equal(got, row.want) {
			t.Errorf("mpi(%v), got %v, want %v", row.input, got, row.want)
		}
	}
}

func TestMpiDecode(t *testing.T) {
	table := []struct {
		input     []byte
		n         int
		i, remain []byte
	}{
		{mpi([]byte{0x01}), 4,
			[]byte{0x00, 0x00, 0x00, 0x01}, []byte{}},
		{mpi([]byte{0x80}), 3,
			[]byte{0x00, 0x00, 0x80}, []byte{}},
		{mpi([]byte{0x80, 0x00}), 2,
			[]byte{0x80, 0x00}, []byte{}},
		{mpi([]byte{0x80, 0x00}), 3,
			[]byte{0x00, 0x80, 0x00}, []byte{}},
		{append(mpi([]byte{0x80, 0x00}), 0xde, 0xad), 2,
			[]byte{0x80, 0x00}, []byte{0xde, 0xad}},
		{append(mpi([]byte{0x80, 0x00}), 0xde, 0xad), 3,
			[]byte{0x00, 0x80, 0x00}, []byte{0xde, 0xad}},
	}

	for _, row := range table {
		i, remain := mpiDecode(row.input, row.n)
		if !bytes.Equal(i, row.i) || !bytes.Equal(remain, row.remain) {
			t.Errorf("mpiDecode([%# x], %d), "+
				"got ([%# x], [%# x]), "+
				"want ([%# x], [%# x])",
				row.input, row.n, i, remain, row.i, row.remain)
		}
	}
}

func TestCRC24(t *testing.T) {
	table := []struct {
		input string
		want  int32
	}{
		{"", 0xb704ce},
		{"hello", 0x47f58a},
		{"The quick brown fox jumper over the lazy dog.", 0x4d2822},
		{string(make([]byte, 16)), 0x900590},
	}

	for _, row := range table {
		got := crc24([]byte(row.input))
		if got != row.want {
			t.Errorf("crc24(%q), got %#x, want %#x", row.input, got, row.want)
		}
	}
}
