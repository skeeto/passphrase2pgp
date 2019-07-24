package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"time"
)

// mask selects the bits to be collided.
const mask = (1 << 64) - 1

// distingish is a mask that determintes the average hash chain length.
// A chain ends when these bits are all zero. This sets the trade-off
// between computation time and memory use.
const distinguish = (1 << 17) - 1

// expand fills a 32-byte key seed from a 64-bit PRNG seed.
func expand(kseed []byte, seed uint64) {
	for i := 0; i < 4; i++ {
		seed += 0x9e3779b97f4a7c15
		z := seed
		z ^= z >> 30
		z *= 0xbf58476d1ce4e5b9
		z ^= z >> 27
		z *= 0x94d049bb133111eb
		z ^= z >> 31
		binary.LittleEndian.PutUint64(kseed[i*8:], z)
	}
}

// link represents a individual link in a hash chain: a seed and its
// resulting truncated key ID.
type link struct {
	seed    uint64
	truncID uint64
}

// Returns the final truncated key ID of a hash chain starting at the
// given seed, as well as the length of the chain. If not nil, the chain
// itself is recorded into the link slice for inspection.
func computeChain(seed uint64, created int64, record *[]link) (uint64, int) {
	var kseed [32]byte
	var key SignKey
	key.SetCreated(created)
	for count := 1; ; count++ {
		expand(kseed[:], seed)
		key.Seed(kseed[:])
		keyID := key.KeyID()
		truncID := binary.BigEndian.Uint64(keyID[12:]) & mask
		if record != nil {
			*record = append(*record, link{seed, truncID})
		}
		seed = truncID
		if truncID&distinguish == 0 {
			return truncID, count
		}
	}
}

// chain represents a complete hash chain: the starting seed, the final
// truncated key ID, and the chain's length.
type chain struct {
	seed    uint64
	truncID uint64
	length  int
}

// Find a long Key ID collision and print it to standard output.
func collide(options *options) {
	chains := make(chan chain)
	seeds := make(chan uint64)

	// Feed unique seeds one at a time to the workers.
	go func() {
		seed := uint64(time.Now().UnixNano())
		seed ^= seed >> 32
		seed *= 0xd6e8feb86659fd93
		seed ^= seed >> 32
		seed *= 0xd6e8feb86659fd93
		seed ^= seed >> 32
		for {
			seeds <- seed
			seed++
		}
	}()

	// Spin off workers to create chains.
	for i := 0; i < runtime.GOMAXPROCS(0); i++ {
		go func() {
			for seed := range seeds {
				truncID, length := computeChain(seed, options.created, nil)
				chains <- chain{seed, truncID, length}
			}
		}()
	}

	var total int64
	seen := make(map[uint64]uint64)
	mean := newMovingAverage(64)
	start := time.Now()

	for chain := range chains {
		total += int64(chain.length)
		if options.verbose {
			rate := mean.add(float64(total))
			fmt.Fprintf(os.Stderr, "chains %d, keys %d, keys/sec %.0f\n",
				len(seen)+1, total, rate)
		}

		if seed, ok := seen[chain.truncID]; ok {
			// Recreate chains, but record all the links this time.
			var recordA, recordB []link
			computeChain(seed, options.created, &recordA)
			computeChain(chain.seed, options.created, &recordB)

			mapB := make(map[uint64]uint64)
			for _, link := range recordB {
				mapB[link.truncID] = link.seed
			}

			for _, link := range recordA {
				seedB, ok := mapB[link.truncID]
				if !ok {
					continue
				}
				seedA := link.seed

				if options.verbose {
					duration := time.Now().Sub(start)
					fmt.Fprintf(os.Stderr, "duration %s\n", duration)
				}

				var buf bytes.Buffer
				userid := UserID{ID: []byte(options.uid)}
				var kseed [32]byte

				// Recreate and self-sign first key
				var keyA SignKey
				expand(kseed[:], seedA)
				keyA.Seed(kseed[:])
				keyA.SetCreated(options.created)
				if options.public {
					buf.Write(keyA.PubPacket())
				} else {
					buf.Write(keyA.Packet())
				}
				buf.Write(userid.Packet())
				buf.Write(keyA.Bind(&userid, options.created))
				armor := Armor(buf.Bytes())
				if _, err := os.Stdout.Write(armor); err != nil {
					fatal("%s", err)
				}
				buf.Truncate(0)

				// Recreate and self-sign second key
				var keyB SignKey
				expand(kseed[:], seedB)
				keyB.Seed(kseed[:])
				keyB.SetCreated(options.created)
				if options.public {
					buf.Write(keyB.PubPacket())
				} else {
					buf.Write(keyB.Packet())
				}
				buf.Write(userid.Packet())
				buf.Write(keyB.Bind(&userid, options.created))
				armor = Armor(buf.Bytes())
				if _, err := os.Stdout.Write(armor); err != nil {
					fatal("%s", err)
				}

				os.Exit(0)
			}
		} else {
			seen[chain.truncID] = chain.seed
		}
	}
}

type sample struct {
	what float64
	when time.Time
}

type movingAverage struct {
	queue      []sample
	head, tail int
}

func newMovingAverage(n int) *movingAverage {
	return &movingAverage{queue: make([]sample, n)}
}

func (m *movingAverage) add(value float64) float64 {
	head := &m.queue[m.head]
	m.head = (m.head + 1) % len(m.queue)
	if m.head == m.tail {
		m.tail = (m.tail + 1) % len(m.queue)
	}
	tail := &m.queue[m.tail]
	head.what = value
	head.when = time.Now()
	num := head.what - tail.what
	den := head.when.Sub(tail.when).Seconds()
	if den == 0.0 {
		return 0.0
	}
	return num / den
}
