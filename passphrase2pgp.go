// This is free and unencumbered software released into the public domain.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	kdfTime    = 8
	kdfMemory  = 1024 * 1024 // 1 GB
	modeKeygen = iota
	modeSign
)

// Print the message like fmt.Printf() and then os.Exit(1).
func fatal(format string, args ...interface{}) {
	buf := bytes.NewBufferString("passphrase2pgp: ")
	fmt.Fprintf(buf, format, args...)
	buf.WriteRune('\n')
	os.Stderr.Write(buf.Bytes())
	os.Exit(1)
}

// Read, confirm, and return a passphrase from the user.
func readPassphrase(repeat int) ([]byte, error) {
	fd := int(syscall.Stdin)
	var out io.Writer = os.Stderr
	if !terminal.IsTerminal(fd) {
		tty, err := os.Create("/dev/tty") // O_RDWR
		if err != nil {
			fatal("failed to open /dev/tty")
		}
		defer tty.Close()
		fd = int(tty.Fd())
		out = tty
	}

	tail := []byte("\n")
	out.Write([]byte("passphrase: "))
	passphrase, err := terminal.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	out.Write(tail)
	for i := 0; i < repeat; i++ {
		out.Write([]byte("passphrase (repeat): "))
		again, err := terminal.ReadPassword(fd)
		if err != nil {
			return nil, err
		}
		out.Write(tail)
		if !bytes.Equal(again, passphrase) {
			return nil, errors.New("passphrases do not match")
		}
	}
	return passphrase, nil
}

// Returns the first line of a file not including \r or \n. Does not
// require a newline and does not return io.EOF.
func firstLine(filename string) ([]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	if !s.Scan() {
		if err := s.Err(); err != io.EOF {
			return nil, err
		}
		return nil, nil // empty files are ok
	}
	return s.Bytes(), nil
}

// Derive a 64-byte seed from the given passphrase. The scale factor
// scales up the difficulty proportional to scale*scale.
func kdf(passphrase, uid []byte, scale int) []byte {
	time := uint32(kdfTime * scale)
	memory := uint32(kdfMemory * scale)
	threads := uint8(1)
	return argon2.IDKey(passphrase, uid, time, memory, threads, 64)
}

type options struct {
	mode   int
	sign   bool // mode
	keygen bool // mode

	args []string

	armor       bool
	created     int64
	fingerprint bool
	help        bool
	input       string
	load        string
	now         bool
	paranoid    bool
	public      bool
	repeat      int
	subkey      bool
	uid         string
}

func parse() *options {
	var o options

	flag.BoolVar(&o.sign, "S", false, "output detached signature for input")
	flag.BoolVar(&o.keygen, "K", true, "output a new key")

	flag.BoolVar(&o.armor, "a", false, "use ASCII armor")
	flag.Int64Var(&o.created, "t", 0, "creation date (unix epoch seconds)")
	flag.BoolVar(&o.fingerprint, "f", false, "also show fingerprint")
	flag.BoolVar(&o.help, "h", false, "print this help message")
	flag.StringVar(&o.input, "i", "", "read passphrase from file")
	flag.StringVar(&o.load, "l", "", "load key from file instead")
	flag.BoolVar(&o.now, "n", false, "use current time as creation date")
	flag.BoolVar(&o.paranoid, "x", false, "paranoid mode")
	flag.BoolVar(&o.public, "p", false, "only output public key")
	flag.IntVar(&o.repeat, "r", 1, "number of repeated passphrase prompts")
	flag.BoolVar(&o.subkey, "s", false, "also output encryption subkey")
	flag.StringVar(&o.uid, "u", "", "user ID for the key")

	flag.Parse()
	if o.sign {
		o.mode = modeSign
	} else {
		o.mode = modeKeygen
	}

	if o.help {
		flag.CommandLine.SetOutput(os.Stdout)
		flag.Usage()
		os.Exit(0)
	}

	if o.uid == "" && o.load == "" {
		// Using os.Getenv instead of os.LookupEnv because empty is just
		// as good as not set. It means a user can do something like:
		// $ EMAIL= passphrase2pgp ...
		if email := os.Getenv("EMAIL"); email != "" {
			if realname := os.Getenv("REALNAME"); realname != "" {
				o.uid = fmt.Sprintf("%s <%s>", realname, email)
			}
		}
		if o.uid == "" {
			fatal("must have either -u or -l option")
		}
	}

	if o.now {
		o.created = time.Now().Unix()
	}

	o.args = flag.Args()
	switch o.mode {
	case modeKeygen:
		if len(o.args) > 0 {
			fatal("too many arguments")
		}
	case modeSign:
		// processed elsewhere
	}

	return &o
}

func main() {
	var key SignKey
	var subkey EncryptKey
	var userid UserID

	options := parse()

	if options.load == "" {
		// Read the passphrase from the terminal
		var passphrase []byte
		var err error
		if options.input != "" {
			passphrase, err = firstLine(options.input)
		} else {
			passphrase, err = readPassphrase(options.repeat)
		}
		if err != nil {
			fatal("%s", err)
		}

		// Run KDF on passphrase
		scale := 1
		if options.paranoid {
			scale = 2 // actually 4x difficulty
		}
		seed := kdf(passphrase, []byte(options.uid), scale)

		key.Seed(seed[:32])
		key.SetCreated(options.created)
		userid = UserID{ID: []byte(options.uid)}
		if options.subkey {
			subkey.Seed(seed[32:])
			subkey.SetCreated(options.created)
		}

	} else {
		// Load passphrase from the first line of a file
		f, err := os.Open(options.load)
		if err != nil {
			fatal("%s", err)
		}
		defer f.Close()
		if err := key.Load(f); err != nil {
			fatal("%s", err)
		}
		if err := userid.Load(f); err != nil {
			fatal("%s", err)
		}
		options.created = key.Created()
	}

	if options.fingerprint {
		fmt.Fprintf(os.Stderr, "%X\n", key.KeyID())
	}

	switch options.mode {
	case modeKeygen:
		var buf bytes.Buffer
		if options.public {
			buf.Write(key.PubPacket())
			buf.Write(userid.Packet())
			buf.Write(key.Bind(&userid, options.created))
			if options.subkey {
				buf.Write(subkey.PubPacket())
				buf.Write(key.Bind(&subkey, options.created))
			}
		} else {
			buf.Write(key.Packet())
			buf.Write(userid.Packet())
			buf.Write(key.Bind(&userid, options.created))
			if options.subkey {
				buf.Write(subkey.Packet())
				buf.Write(key.Bind(&subkey, options.created))
			}
		}
		output := buf.Bytes()
		if options.armor {
			output = Armor(output)
		}
		if _, err := os.Stdout.Write(output); err != nil {
			fatal("%s", err)
		}

	case modeSign:
		if len(options.args) == 0 {
			// stdin to stdout
			output, err := key.Sign(os.Stdin)
			if err != nil {
				fatal("%s", err)
			}
			if options.armor {
				output = Armor(output)
			}
			_, err = os.Stdout.Write(output)
			if err != nil {
				fatal("%s", err)
			}

		} else {
			// file by file
			var ext string
			if options.armor {
				ext = ".asc"
			} else {
				ext = ".sig"
			}

			for _, infile := range options.args {
				// Open input file first
				in, err := os.Open(infile)
				if err != nil {
					fatal("%s: %s", err, infile)
				}

				// Create output file second (before reading input)
				outfile := infile + ext
				out, err := os.Create(outfile)
				if err != nil {
					fatal("%s: %s", err, outfile)
				}

				// Process input, cleaning up on error
				output, err := key.Sign(in)
				if err != nil {
					out.Close()
					os.Remove(outfile)
					fatal("%s: %s", err, infile)
				}
				if options.armor {
					output = Armor(output)
				}

				// Write output, cleaning up on error
				_, err = out.Write(output)
				out.Close()
				if err != nil {
					os.Remove(outfile)
					fatal("%s: %s", err, outfile)
				}
			}
		}
	}
}
