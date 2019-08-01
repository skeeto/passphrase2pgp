package main

import "testing"

func TestDecode(t *testing.T) {
	table := []struct {
		input string
		want  string
		ok    bool
	}{
		{"foo", "foo", true},
		{"foo%25", "foo%", true},
		{"a%3d0", "a=0", true},
		{"%ff%00%0a", "\xff\x00\n", true},
		{"%", "", false},
		{"%0", "", false},
		{"%xx", "", false},
	}

	for _, row := range table {
		input := row.input
		got, ok := pinentryDecode(input)
		want := row.want
		if string(got) != want || ok != row.ok {
			t.Errorf("decode(%#v), got %#v/%v, want %#v/%v",
				input, string(got), ok, want, row.ok)
		}
	}
}
