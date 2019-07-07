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
