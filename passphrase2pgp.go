// This is free and unencumbered software released into the public domain.

package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/skeeto/optparse-go"
	"github.com/skeeto/passphrase2pgp/openpgp"
	"golang.org/x/crypto/argon2"
)

const (
	kdfTime   = 8
	kdfMemory = 1024 * 1024 // 1 GB

	defaultExpires = "2y"

	cmdKey = iota
	cmdSign
	cmdClearsign

	formatPGP = iota
	formatSSH
)

// Print the message like fmt.Printf() and then os.Exit(1).
func fatal(format string, args ...interface{}) {
	buf := bytes.NewBufferString("passphrase2pgp: ")
	fmt.Fprintf(buf, format, args...)
	buf.WriteRune('\n')
	os.Stderr.Write(buf.Bytes())
	os.Exit(1)
}

// Read and confirm the passphrase per the user's preference.
func readPassphrase(pinentry, hint string, repeat int) ([]byte, error) {
	if pinentry != "" {
		return pinentryPassphrase(pinentry, hint, repeat)
	}
	return terminalPassphrase(hint, repeat)
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
	protect  bool
	format   int
	help     bool
	input    string
	load     string
	pinentry string
	public   bool
	repeat   int
	subkey   bool
	created  int64
	uid      string
	verbose  bool
	expires  int64

	passphrase      []byte
	protectPassword []byte
	protectQuery    int
}

func usage(w io.Writer) {
	bw := bufio.NewWriter(w)
	i := "  "
	b := "      "
	p := "passphrase2pgp"
	f := func(s ...interface{}) {
		fmt.Fprintln(bw, s...)
	}
	f("Usage:")
	f(i, p, "<-u id|-l key> [-hv] [-c id] [-i pwfile] [--pinentry[=cmd]]")
	f(b, "-K [-anps] [-e[n]] [-f pgp|ssh] [-r n] [-t secs] [-x[spec]]")
	f(b, "-S [-a] [-r n] [files...]")
	f(b, "-T [-r n] >doc-signed.txt <doc.txt")
	f("Commands:")
	f(i, "-K, --key              output a key (default)")
	f(i, "-S, --sign             output detached signatures")
	f(i, "-T, --clearsign        output a cleartext signature")
	f("Options:")
	f(i, "-a, --armor            encode output in ASCII armor")
	f(i, "-c, --check KEYID      require last Key ID bytes to match")
	f(i, "-e, --protect[=ASKS]   protect private key with S2K")
	f(i, "-f, --format pgp|ssh   select key format [pgp]")
	f(i, "-h, --help             print this help message")
	f(i, "-i, --input FILE       read passphrase from file")
	f(i, "-l, --load FILE        load key from file instead of generating")
	f(i, "-n, --now              use current time as creation date")
	f(i, "--pinentry[=CMD]       use pinentry to read the passphrase")
	f(i, "-p, --public           only output the public key")
	f(i, "-r, --repeat N         number of repeated passphrase prompts")
	f(i, "-s, --subkey           also output an encryption subkey")
	f(i, "-t, --time SECONDS     key creation date (unix epoch seconds)")
	f(i, "-u, --uid USERID       user ID for the key")
	f(i, "-v, --verbose          print additional information")
	f(i, "-x, --expires[=SPEC]   set key expiration time ["+defaultExpires+"]")
	bw.Flush()
}

func parse() *config {
	conf := config{
		cmd:    cmdKey,
		format: formatPGP,
		repeat: 1,
	}

	options := []optparse.Option{
		{"sign", 'S', optparse.KindNone},
		{"keygen", 'K', optparse.KindNone},
		{"clearsign", 'T', optparse.KindNone},

		{"armor", 'a', optparse.KindNone},
		{"check", 'c', optparse.KindRequired},
		{"protect", 'e', optparse.KindOptional},
		{"format", 'f', optparse.KindRequired},
		{"help", 'h', optparse.KindNone},
		{"input", 'i', optparse.KindRequired},
		{"load", 'l', optparse.KindRequired},
		{"now", 'n', optparse.KindNone},
		{"public", 'p', optparse.KindNone},
		{"pinentry", 0, optparse.KindOptional},
		{"public", 'p', optparse.KindNone},
		{"repeat", 'r', optparse.KindRequired},
		{"subkey", 's', optparse.KindNone},
		{"time", 't', optparse.KindRequired},
		{"uid", 'u', optparse.KindRequired},
		{"verbose", 'v', optparse.KindNone},
		{"expires", 'x', optparse.KindOptional},
	}

	var repeatSeen bool
	var uidSeen bool
	var timeSeen bool

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
		case "clearsign":
			conf.cmd = cmdClearsign

		case "armor":
			conf.armor = true
		case "check":
			check, err := hex.DecodeString(result.Optarg)
			if err != nil {
				fatal("%s: %q", err, result.Optarg)
			}
			conf.check = check
		case "protect":
			conf.protect = true
			if result.Optarg != "" {
				repeat, err := strconv.Atoi(result.Optarg)
				if err != nil {
					fatal("--protect (-e): %s", err)
				}
				conf.protectQuery = repeat
			}
		case "format":
			switch result.Optarg {
			case "pgp":
				conf.format = formatPGP
			case "ssh":
				conf.format = formatSSH
			default:
				fatal("invalid format: %s", result.Optarg)
			}
		case "help":
			usage(os.Stdout)
			os.Exit(0)
		case "input":
			conf.input = result.Optarg
		case "load":
			conf.load = result.Optarg
		case "now":
			conf.created = time.Now().Unix()
			timeSeen = true
		case "pinentry":
			if result.Optarg != "" {
				conf.pinentry = result.Optarg
			} else {
				conf.pinentry = "pinentry"
			}
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
			timeSeen = true
		case "uid":
			conf.uid = result.Optarg
			if len(conf.uid) > 255 {
				fatal("user ID length must be <= 255 bytes")
			}
			if !utf8.ValidString(conf.uid) {
				fatal("user ID must be valid UTF-8")
			}
			uidSeen = true
		case "verbose":
			conf.verbose = true
		case "expires":
			conf.expires = timespec(result.Optarg)
		}
	}

	if !uidSeen && conf.load == "" {
		// Using os.Getenv instead of os.LookupEnv because empty is just
		// as good as not set. It means a user can do something like:
		// $ EMAIL= passphrase2pgp ...
		if email := os.Getenv("EMAIL"); email != "" {
			if realname := os.Getenv("REALNAME"); realname != "" {
				conf.uid = fmt.Sprintf("%s <%s>", realname, email)
			}
		}
		if conf.uid == "" {
			fatal("--uid or --load required (or $REALNAME and $EMAIL)")
		}
	}

	if conf.load != "" && !timeSeen {
		conf.created = time.Now().Unix()
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

	if conf.expires != 0 {
		delta := conf.expires - conf.created
		if delta > 0xffffffff {
			// Delta between created date and expiration must fit in a
			// 32-bit integer. According to RFC 4880, this should
			// treated as a uint32. However, GnuPG (as of 2.2.12) treats
			// it as int32, allowing for nonsensical negative values
			// (keys can expire before they were created) and cutting
			// the range in half. This is a GnuPG bug, but hopefully
			// it will be fixed before it becomes a problem.
			fatal("key expiration too far in the future")
			// Side note: Another GnuPG bug is that it doesn't properly
			// process expiration dates for keys with a zero creation
			// date (i.e. passphrase2pgp keys), and instead treats such
			// keys as having no expiration date. Hopefully this is
			// fixed someday, too.
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
	case cmdClearsign:
		if len(conf.args) > 1 {
			fatal("too many arguments")
		}
	}

	return &conf
}

// Return a key expiration date from the given "timespec" string. See
// the README for format information.
func timespec(ts string) int64 {
	if ts == "" {
		ts = defaultExpires
	}

	unit := ts[len(ts)-1]
	value := ts
	var duration time.Duration

	switch unit {
	case 'd':
		value = ts[:len(ts)-1]
		duration = time.Hour * 24
	case 'w':
		value = ts[:len(ts)-1]
		duration = time.Hour * 24 * 7
	case 'm':
		value = ts[:len(ts)-1]
		duration = time.Hour * 24 * 30
	case 'y':
		value = ts[:len(ts)-1]
		duration = time.Hour * 24 * 365
	}

	t, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		fatal("timespec, %s: %s", err, ts)
	}
	if duration != 0 {
		t = time.Now().Unix() + int64(duration.Seconds())*t
	}

	if t < 0 {
		fatal("timespec cannot be negative: %s", ts)
	}
	return t
}

func main() {
	var key openpgp.SignKey
	var subkey openpgp.EncryptKey
	var userid openpgp.UserID

	config := parse()

	if config.load == "" {
		if config.verbose {
			fmt.Fprintf(os.Stderr, "User ID: %s\n", config.uid)
		}

		// Read the passphrase from the terminal
		var err error
		if config.input != "" {
			config.passphrase, err = firstLine(config.input)
		} else {
			pinentry := config.pinentry
			repeat := config.repeat
			config.passphrase, err = readPassphrase(pinentry, "", repeat)
		}
		if err != nil {
			fatal("%s", err)
		}

		// Run KDF on passphrase
		scale := 1
		seed := kdf(config.passphrase, []byte(config.uid), scale)

		key.Seed(seed[:32])
		key.SetCreated(config.created)
		key.SetExpires(config.expires)
		userid = openpgp.UserID{[]byte(config.uid)}
		if config.subkey {
			subkey.Seed(seed[32:])
			subkey.SetCreated(config.created)
			subkey.SetExpires(config.expires)
		}

	} else {
		// Load keys from previous output
		packets, err := parsePackets(config.load)
		if err != nil {
			fatal("%s", err)
		}
		if len(packets) < 3 {
			fatal("invalid input (too few packets)")
		}
		config.created = time.Now().Unix()

		if err := key.Load(packets[0], nil); err != nil {
			if err != openpgp.ErrDecryptKey {
				fatal("%s", err)
			}
			pinentry := config.pinentry
			repeat := config.protectQuery - 1
			password, err := readPassphrase(pinentry, "protection", repeat)
			if err != nil {
				fatal("%s", err)
			}
			config.protectPassword = password
			if err := key.Load(packets[0], password); err != nil {
				fatal("%s", err)
			}
		}

		if err := userid.Load(packets[1]); err != nil {
			fatal("%s", err)
		}
		if config.verbose {
			fmt.Fprintf(os.Stderr, "User ID: %s\n", userid.ID)
		}

		config.subkey = false
		if len(packets) >= 5 {
			password := config.protectPassword
			if err := subkey.Load(packets[3], password); err != nil {
				fatal("%s", err)
			}
			config.subkey = true
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
		ck := completeKey{&key, &userid, &subkey}
		switch config.format {
		case formatPGP:
			ck.outputPGP(config)
		case formatSSH:
			ck.outputSSH(config)
		}

	case cmdSign:
		if len(config.args) == 0 {
			// stdin to stdout
			output, err := key.Sign(os.Stdin)
			if err != nil {
				fatal("%s", err)
			}
			if config.armor {
				output = openpgp.Armor(output)
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
					output = openpgp.Armor(output)
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

	case cmdClearsign:
		out := bufio.NewWriter(os.Stdout)
		var in io.Reader
		var f *os.File
		if len(config.args) == 1 {
			var err error
			f, err = os.Open(config.args[0])
			if err != nil {
				fatal("%s", err)
			}
			in = key.Clearsign(f)
		} else {
			in = key.Clearsign(os.Stdin)
		}

		// Pump input through filter
		if _, err := io.Copy(out, in); err != nil {
			fatal("%s", err)
		}
		if err := out.Flush(); err != nil {
			fatal("%s", err)
		}

		if f != nil {
			f.Close()
		}
	}
}

type completeKey struct {
	key    *openpgp.SignKey
	userid *openpgp.UserID
	subkey *openpgp.EncryptKey
}

func (k *completeKey) outputPGP(config *config) {
	key := k.key
	userid := k.userid
	subkey := k.subkey

	flags := 0
	if config.subkey {
		flags |= openpgp.FlagMDC
	}

	var buf bytes.Buffer
	if config.public {
		buf.Write(key.PubPacket())
		buf.Write(userid.Packet())
		buf.Write(key.SelfSign(userid, config.created, flags))
		if config.subkey {
			buf.Write(subkey.PubPacket())
			buf.Write(key.Bind(subkey, config.created))
		}
	} else {
		if config.protectQuery > 0 && config.protectPassword == nil {
			var err error
			pinentry := config.pinentry
			repeat := config.protectQuery - 1
			password, err := readPassphrase(pinentry, "protection", repeat)
			if err != nil {
				fatal("%s", err)
			}
			config.protectPassword = password
		} else if config.protectPassword == nil {
			config.protectPassword = config.passphrase
		}

		if config.protect {
			buf.Write(key.EncPacket(config.protectPassword))
		} else {
			buf.Write(key.Packet())
		}
		buf.Write(userid.Packet())
		buf.Write(key.SelfSign(userid, config.created, flags))
		if config.subkey {
			if config.protect {
				buf.Write(subkey.EncPacket(config.protectPassword))
			} else {
				buf.Write(subkey.Packet())
			}
			buf.Write(key.Bind(subkey, config.created))
		}
	}
	output := buf.Bytes()

	if config.armor {
		output = openpgp.Armor(output)
	}
	if _, err := os.Stdout.Write(output); err != nil {
		fatal("%s", err)
	}
}

// PEM-encode a string
func pem(str []byte) []byte {
	buf := make([]byte, len(str)+4)
	binary.BigEndian.PutUint32(buf, uint32(len(str)))
	copy(buf[4:], str)
	return buf
}

func (k *completeKey) outputSSH(config *config) {
	// packet is the binary form of the PEM encoding
	var packet bytes.Buffer
	packet.Write([]byte("openssh-key-v1\x00")) // magic
	packet.Write(pem([]byte("none")))          // ciphername
	packet.Write(pem([]byte("none")))          // kdfname
	packet.Write(pem([]byte{}))                // kdfoptions
	packet.Write([]byte{0, 0, 0, 1})           // number of keys

	// Public key (nested PEM)
	var pubkey bytes.Buffer
	pubkey.Write(pem([]byte("ssh-ed25519")))
	pubkey.Write(pem(k.key.Pubkey()))
	packet.Write(pem(pubkey.Bytes()))

	// Private key (nested PEM)
	var seckey bytes.Buffer
	seckey.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0}) // check bytes
	seckey.Write(pem([]byte("ssh-ed25519")))
	seckey.Write(pem(k.key.Pubkey()))
	concat := append(k.key.Seckey()[0:32:32], k.key.Pubkey()...)
	// (Yes, the public key has appeared three times now!)
	seckey.Write(pem(concat))
	seckey.Write(pem(k.userid.ID))
	for i := 1; seckey.Len()%8 != 0; i++ {
		seckey.Write([]byte{byte(i)})
	}
	packet.Write(pem(seckey.Bytes()))

	// Encode the binary packet as base64
	var packet64 bytes.Buffer
	encoding := base64.RawStdEncoding.WithPadding('=')
	b64 := base64.NewEncoder(encoding, &packet64)
	b64.Write(packet.Bytes())
	b64.Close()

	// Wrap the base64 encoding into PEM ASCII format
	var sec bytes.Buffer
	sec.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	data := packet64.Bytes()
	// Pad to 8 bytes
	for len(data) > 0 {
		n := 70
		if len(data) < n {
			n = len(data)
		}
		sec.Write(data[:n])
		sec.WriteByte(0x0a)
		data = data[n:]
	}
	sec.WriteString("-----END OPENSSH PRIVATE KEY-----\n")

	// Prepare the public key output (one line)
	var pub bytes.Buffer
	pub.WriteString("ssh-ed25519 ")
	b64 = base64.NewEncoder(encoding, &pub)
	var pubpacket bytes.Buffer
	pubpacket.Write(pem([]byte("ssh-ed25519")))
	pubpacket.Write(pem(k.key.Pubkey()))
	b64.Write(pubpacket.Bytes())
	pub.WriteByte(0x20)
	pub.Write(k.userid.ID)
	pub.WriteByte(0x0a)

	if !config.public {
		if _, err := os.Stdout.Write(sec.Bytes()); err != nil {
			fatal("%s", err)
		}
	}
	if _, err := os.Stdout.Write(pub.Bytes()); err != nil {
		fatal("%s", err)
	}
}

func parsePackets(filename string) ([]openpgp.Packet, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(data) < 1 {
		return nil, openpgp.ErrInvalidPacket
	}

	if data[0] < 128 {
		var err error
		data, err = openpgp.Dearmor(data)
		if err != nil {
			return nil, err
		}
	}

	var packets []openpgp.Packet
	for len(data) > 0 {
		var err error
		var packet openpgp.Packet
		packet, data, err = openpgp.ParsePacket(data)
		if err != nil {
			return nil, err
		}
		packets = append(packets, packet)
	}
	return packets, nil
}
