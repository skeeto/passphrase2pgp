// This is free and unencumbered software released into the public domain.

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"syscall"
	"time"

	"github.com/skeeto/optparse-go"
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
	mode int
	args []string

	armor       bool
	created     int64
	fingerprint bool
	help        bool
	input       string
	load        string
	paranoid    bool
	public      bool
	repeat      int
	subkey      bool
	uid         string
}

func usage(w io.Writer) {
	bw := bufio.NewWriter(w)
	p := "passphrase2pgp"
	i := "  "
	f := func(s ...interface{}) {
		fmt.Fprintln(bw, s...)
	}
	f("Usage:")
	f(i, p, "-K <-u id|-l key> [-afhnpsx] [-i ppfile] [-r n] [-t time]")
	f(i, p, "-S <-u id|-l key> [-afh] [-i ppfile] [-r n] [files...]")
	f("Modes:")
	f(i, "-S, --sign    create a detached signature")
	f(i, "-K, --keygen  generate and output a key (default mode)")
	f("Options:")
	f(i, "-a, --armor            encode output in ASCII armor")
	f(i, "-f, --fingerprint      also print fingerprint to standard error")
	f(i, "-h, --help             print this help message")
	f(i, "-i, --input FILE       read passphrase from file")
	f(i, "-l, --load FILE        load key from file instead of generating")
	f(i, "-n, --now              use current time as creation date")
	f(i, "-p, --public           only output the public key")
	f(i, "-r, --repeat N         number of repeated passphrase prompts")
	f(i, "-s, --subkey           also output an encryption subkey")
	f(i, "-t, --time SECONDS     key creation date (unix epoch seconds)")
	f(i, "-u, --uid USERID       user ID for the key")
	f(i, "-x, --paranoid         increase key generation costs")
	bw.Flush()
}

func parse() *options {
	opt := options{
		mode:   modeKeygen,
		repeat: 1,
	}

	options := []optparse.Option{
		{"sign", 'S', optparse.KindNone},
		{"keygen", 'K', optparse.KindNone},

		{"armor", 'a', optparse.KindNone},
		{"fingerprint", 'f', optparse.KindNone},
		{"help", 'h', optparse.KindNone},
		{"input", 'i', optparse.KindRequired},
		{"load", 'l', optparse.KindRequired},
		{"now", 'n', optparse.KindNone},
		{"public", 'p', optparse.KindNone},
		{"repeat", 'r', optparse.KindRequired},
		{"subkey", 's', optparse.KindNone},
		{"time", 't', optparse.KindRequired},
		{"uid", 'u', optparse.KindRequired},
		{"paranoid", 'x', optparse.KindNone},
	}

	results, rest, err := optparse.Parse(options, os.Args)
	if err != nil {
		usage(os.Stderr)
		fatal("%s", err)
	}
	for _, result := range results {
		switch result.Long {
		case "sign":
			opt.mode = modeSign
		case "keygen":
			opt.mode = modeKeygen

		case "armor":
			opt.armor = true
		case "fingerprint":
			opt.fingerprint = true
		case "help":
			usage(os.Stdout)
			os.Exit(0)
		case "input":
			opt.input = result.Optarg
		case "load":
			opt.load = result.Optarg
		case "now":
			opt.created = time.Now().Unix()
		case "public":
			opt.public = true
		case "repeat":
			repeat, err := strconv.Atoi(result.Optarg)
			if err != nil {
				fatal("--repeat (-r): %s", err)
			}
			opt.repeat = repeat
		case "subkey":
			opt.subkey = true
		case "time":
			time, err := strconv.ParseUint(result.Optarg, 10, 32)
			if err != nil {
				fatal("--time (-t): %s", err)
			}
			opt.created = int64(time)
		case "uid":
			opt.uid = result.Optarg
		case "paranoid":
			opt.paranoid = true
		}
	}

	if opt.uid == "" && opt.load == "" {
		// Using os.Getenv instead of os.LookupEnv because empty is just
		// as good as not set. It means a user can do something like:
		// $ EMAIL= passphrase2pgp ...
		if email := os.Getenv("EMAIL"); email != "" {
			if realname := os.Getenv("REALNAME"); realname != "" {
				opt.uid = fmt.Sprintf("%s <%s>", realname, email)
			}
		}
		if opt.uid == "" {
			fatal("must have either -u or -l option")
		}
	}

	opt.args = rest
	switch opt.mode {
	case modeKeygen:
		if len(opt.args) > 0 {
			fatal("too many arguments")
		}
	case modeSign:
		// processed elsewhere
	}

	return &opt
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
		in, err := os.Open(options.load)
		if err != nil {
			fatal("%s", err)
		}
		defer in.Close()
		bufin := bufio.NewReader(in)
		if err := key.Load(bufin); err != nil {
			fatal("%s", err)
		}
		if err := userid.Load(bufin); err != nil {
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
