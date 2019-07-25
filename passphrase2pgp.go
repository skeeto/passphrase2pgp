// This is free and unencumbered software released into the public domain.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
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
	kdfTime   = 8
	kdfMemory = 1024 * 1024 // 1 GB

	cmdKey = iota
	cmdSign
	cmdCollide
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

type config struct {
	cmd  int
	args []string

	armor    bool
	check    []byte
	help     bool
	input    string
	load     string
	public   bool
	repeat   int
	subkey   bool
	created  int64
	uid      string
	verbose  bool
	paranoid bool
}

func usage(w io.Writer) {
	bw := bufio.NewWriter(w)
	p := "passphrase2pgp"
	i := "  "
	f := func(s ...interface{}) {
		fmt.Fprintln(bw, s...)
	}
	f("Usage:")
	f(i, p, "-K <-u id|-l key> [-anpsvx] [-i ppfile] [-r n] [-t time]")
	f(i, p, "-S <-u id|-l key> [-av] [-i ppfile] [-r n] [files...]")
	f("Commands:")
	f(i, "-K, --key              output a key (default)")
	f(i, "-S, --sign             output detached signatures")
	f("Options:")
	f(i, "-a, --armor            encode output in ASCII armor")
	f(i, "-c, --check KEYID      require last Key ID bytes to match")
	f(i, "-h, --help             print this help message")
	f(i, "-i, --input FILE       read passphrase from file")
	f(i, "-l, --load FILE        load key from file instead of generating")
	f(i, "-n, --now              use current time as creation date")
	f(i, "-p, --public           only output the public key")
	f(i, "-r, --repeat N         number of repeated passphrase prompts")
	f(i, "-s, --subkey           also output an encryption subkey")
	f(i, "-t, --time SECONDS     key creation date (unix epoch seconds)")
	f(i, "-u, --uid USERID       user ID for the key")
	f(i, "-v, --verbose          print additional information")
	f(i, "-x, --paranoid         increase key generation costs")
	bw.Flush()
}

func parse() *config {
	conf := config{
		cmd:    cmdKey,
		repeat: 1,
	}

	options := []optparse.Option{
		{"sign", 'S', optparse.KindNone},
		{"keygen", 'K', optparse.KindNone},
		{"collide", 'X', optparse.KindNone},

		{"armor", 'a', optparse.KindNone},
		{"check", 'c', optparse.KindRequired},
		{"help", 'h', optparse.KindNone},
		{"input", 'i', optparse.KindRequired},
		{"load", 'l', optparse.KindRequired},
		{"now", 'n', optparse.KindNone},
		{"public", 'p', optparse.KindNone},
		{"repeat", 'r', optparse.KindRequired},
		{"subkey", 's', optparse.KindNone},
		{"time", 't', optparse.KindRequired},
		{"uid", 'u', optparse.KindRequired},
		{"verbose", 'v', optparse.KindNone},
		{"paranoid", 'x', optparse.KindNone},
	}

	var repeatSeen bool

	args := os.Args
	if len(args) == 4 && args[1] == "--status-fd=2" && args[2] == "-bsau" {
		// Pretend to be GnuPG in order to sign for Git. Unfortunately
		// this is fragile, but there's no practical way to avoid it.
		// The Git documentation says it depends on the GnuPG interface
		// without being specific, so the only robust solution is to
		// re-implement the entire GnuPG interface.
		args = []string{args[0], "--sign", "--armor", "--uid", args[3]}
		os.Stderr.WriteString("\n[GNUPG:] SIG_CREATED ")
	}

	results, rest, err := optparse.Parse(options, args)
	if err != nil {
		usage(os.Stderr)
		fatal("%s", err)
	}
	for _, result := range results {
		switch result.Long {
		case "sign":
			conf.cmd = cmdSign
		case "keygen":
			conf.cmd = cmdKey
		case "collide":
			conf.cmd = cmdCollide

		case "armor":
			conf.armor = true
		case "check":
			check, err := hex.DecodeString(result.Optarg)
			if err != nil {
				fatal("%s: %q", err, result.Optarg)
			}
			conf.check = check
		case "help":
			usage(os.Stdout)
			os.Exit(0)
		case "input":
			conf.input = result.Optarg
		case "load":
			conf.load = result.Optarg
		case "now":
			conf.created = time.Now().Unix()
		case "public":
			conf.public = true
		case "repeat":
			repeat, err := strconv.Atoi(result.Optarg)
			if err != nil {
				fatal("--repeat (-r): %s", err)
			}
			conf.repeat = repeat
			repeatSeen = true
		case "subkey":
			conf.subkey = true
		case "time":
			time, err := strconv.ParseUint(result.Optarg, 10, 32)
			if err != nil {
				fatal("--time (-t): %s", err)
			}
			conf.created = int64(time)
		case "uid":
			conf.uid = result.Optarg
		case "verbose":
			conf.verbose = true
		case "paranoid":
			conf.paranoid = true
		}
	}

	if conf.uid == "" && conf.load == "" {
		// Using os.Getenv instead of os.LookupEnv because empty is just
		// as good as not set. It means a user can do something like:
		// $ EMAIL= passphrase2pgp ...
		if email := os.Getenv("EMAIL"); email != "" {
			if realname := os.Getenv("REALNAME"); realname != "" {
				conf.uid = fmt.Sprintf("%s <%s>", realname, email)
			}
		}
		if conf.uid == "" {
			fatal("must have either -u or -l option")
		}
	}

	if conf.check == nil {
		check, err := hex.DecodeString(os.Getenv("KEYID"))
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: $KEYID invalid, ignoring it\n")
		} else {
			conf.check = check
		}
	}
	if len(conf.check) > 0 {
		if !repeatSeen {
			conf.repeat = 0
		}
	}

	conf.args = rest
	switch conf.cmd {
	case cmdKey:
		if len(conf.args) > 0 {
			fatal("too many arguments")
		}
	case cmdSign:
		// processed elsewhere
	case cmdCollide:
		collide(&conf)
	}

	return &conf
}

func main() {
	var key SignKey
	var subkey EncryptKey
	var userid UserID

	config := parse()

	if config.load == "" {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "User ID: %s\n", config.uid)
		}

		// Read the passphrase from the terminal
		var passphrase []byte
		var err error
		if config.input != "" {
			passphrase, err = firstLine(config.input)
		} else {
			passphrase, err = readPassphrase(config.repeat)
		}
		if err != nil {
			fatal("%s", err)
		}

		// Run KDF on passphrase
		scale := 1
		if config.paranoid {
			scale = 2 // actually 4x difficulty
		}
		seed := kdf(passphrase, []byte(config.uid), scale)

		key.Seed(seed[:32])
		key.SetCreated(config.created)
		userid = UserID{
			ID: []byte(config.uid),
			EnableMDC: config.subkey,
		}
		if config.subkey {
			subkey.Seed(seed[32:])
			subkey.SetCreated(config.created)
		}

	} else {
		// Load passphrase from the first line of a file
		in, err := os.Open(config.load)
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
		config.created = key.Created()

		if config.verbose {
			fmt.Fprintf(os.Stderr, "User ID: %s\n", userid.ID)
		}
	}

	keyid := key.KeyID()
	if config.verbose {
		fmt.Fprintf(os.Stderr, "Key ID: %X\n", keyid)
	}
	checked := keyid[len(keyid)-len(config.check):]
	if !bytes.Equal(config.check, checked) {
		fatal("Key ID does not match --check (-c):\n  %X != %X",
			checked, config.check)
	}

	switch config.cmd {
	case cmdKey:
		var buf bytes.Buffer
		if config.public {
			buf.Write(key.PubPacket())
			buf.Write(userid.Packet())
			buf.Write(key.Bind(&userid, config.created))
			if config.subkey {
				buf.Write(subkey.PubPacket())
				buf.Write(key.Bind(&subkey, config.created))
			}
		} else {
			buf.Write(key.Packet())
			buf.Write(userid.Packet())
			buf.Write(key.Bind(&userid, config.created))
			if config.subkey {
				buf.Write(subkey.Packet())
				buf.Write(key.Bind(&subkey, config.created))
			}
		}
		output := buf.Bytes()
		if config.armor {
			output = Armor(output)
		}
		if _, err := os.Stdout.Write(output); err != nil {
			fatal("%s", err)
		}

	case cmdSign:
		if len(config.args) == 0 {
			// stdin to stdout
			output, err := key.Sign(os.Stdin)
			if err != nil {
				fatal("%s", err)
			}
			if config.armor {
				output = Armor(output)
			}
			_, err = os.Stdout.Write(output)
			if err != nil {
				fatal("%s", err)
			}

		} else {
			// file by file
			var ext string
			if config.armor {
				ext = ".asc"
			} else {
				ext = ".sig"
			}

			for _, infile := range config.args {
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
				if config.armor {
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
