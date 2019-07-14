# Predictable, passphrase-based PGP key generator

passphrase2pgp generates, in OpenPGP format, an EdDSA signing key and
Curve25519 encryption subkey entirely from a passphrase, essentially
allowing you to store a backup of your PGP keys in your brain. At any
time you can re-run the tool and re-enter the passphrase to reproduce
the original keys.

The keys are derived from the passphrase and User ID (as salt) using
[Argon2id][argon2] (memory=1GB and time=8) and [RFC 8032][rfc8032]. It's
aggressive enough to protect from offline brute force attacks
passphrases short enough to be memorable by humans. Always use [a strong
passphrase][dw].

Requires Go 1.9 or later.

[argon2]: https://github.com/P-H-C/phc-winner-argon2
[rfc8032]: https://tools.ietf.org/html/rfc8032
[dw]: https://en.wikipedia.org/wiki/Diceware

## Installation

    $ go get -u github.com/skeeto/passphrase2pgp

## Usage

Quick start: Provide a user ID (`-u`) and pipe the output into GnuPG.

    $ passphrase2pgp -u "Real Name <name@example.com>" | gpg --import

Usage summary:

    passphrase2pgp -K <-u id|-l key> [-afhnpsx] [-i ppfile] [-r n] [-t time]
    passphrase2pgp -S <-u id|-l key> [-afh] [-i ppfile] [-r n] [files...]

**Either `-u` or `-l` is required.**

* The `-u` option supplies the user ID string for the key to be
  generated. If `-u` is missing, the `REALNAME` and `EMAIL`
  environmental variables are used to construct a user ID, but only if
  both are present.

* The `-l` option loads a previously generated key for use in other
  operations (signatures, print an ASCII-armored public key, etc.).

There are two modes of operation:

* Key generation (`-K`, default): Writes a key to standard output. This
  is a secret key by default, but `-p` restricts it to a public key.

* Detached signatures (`-S`): Signs one or more input files. Unless `-l`
  is used, also generates a key, but that key is not output. If no files
  are given, signs standard input to standard output. Otherwise for each
  argument `file` creates `file.sig` with a detached signature. If armor
  is enabled (`-a`), the file is named `file.asc`.

Use `-h` for a full option listing:

    Usage of passphrase2pgp:
      -K	output a new key (default true)
      -S	output detached signature for input
      -a	use ASCII armor
      -f	also show fingerprint
      -h	print this help message
      -i string
        	read passphrase from file
      -l string
        	load key from file instead
      -n	use current time as creation date
      -p	only output public key
      -r int
        	number of repeated passphrase prompts (default 1)
      -s	also output encryption subkey
      -t int
        	creation date (unix epoch seconds)
      -u string
        	user ID for the key
      -x	paranoid mode

Per the OpenPGP specification, **the Key ID is a hash over both the key
and its creation date.** Therefore using a different date with the same
passphrase/ID will result in a different Key ID, despite the underlying
key being the same. For this reason, passphrase2pgp uses Unix epoch 0
(January 1, 1970) as the default creation date. You can override this
with `-t` or `-n`, but, to regenerate the same key in the future, you
will need to use `-t` to reenter the exact time. If 1970 is a problem,
then choose another memorable date.

The `-x` (paranoid) setting quadruples the KDF difficulty. This will
result in a different key for the same passphrase.

### Examples

Generate a private key and send it to GnuPG:

    $ passphrase2pgp -u "..." | gnupg --import

Create an armored public key for publishing and sharing:

    $ passphrase2pgp -u "..." -a -p > Real-Name.asc

Determine `-u` from the environment so that you don't need to type it
out every time you use passphrase2pgp:

    $ export REALNAME="Real Name"
    $ export EMAIL="name@example.com"
    $ passphrase2pgp -a -p > Real-Name.asc

Generate a private key and save it to a file in OpenPGP format for later
use below:

    $ passphrase2pgp -u "..." > secret.pgp

Created detached signatures (`-S`) for some files:

    $ passphrase2pgp -S -l secret.pgp document.txt avatar.jpg

This will create `document.txt.sig` and `avatar.jpg.sig`. The other end
would use GnuPG to verify the signatures like so:

    $ gpg --import Real-Name.asc
    $ gpg --verify document.txt.sig
    $ gpg --verify avatar.jpg.sig

Or, in order to avoid entering the passphrase again and waiting on key
generation, use the previously saved private key to sign some files
without entering your passphrase:

    $ passphrase2pgp -S -l secret.pgp document.txt avatar.jpg

Same, but now with ASCII-armored signatures:

    $ passphrase2pgp -S -l secret.pgp -a document.txt avatar.jpg
    $ gpg --verify document.txt.asc
    $ gpg --verify avatar.jpg.asc

### Interacting with GnuPG

Once your key is generated, you may want to secure it with a protection
passphrase on your GnuPG keyring in order to protect it at rest:

    $ gpg --edit-key "Real Name"
    gpg> passwd

Trust is stored external to keys, so imported keys are always initially
untrusted. You will likely want to mark your newly-imported primary key
as trusted.

    $ gpg --edit-key "Real Name"
    gpg> trust

Or use the `--trusted-key` option in `gpg.conf`.

#### Signing Git tags and commits

It's even possible to use passphrase2pgp directly to sign your Git tags
and commits. First create a script with these contents, options adjusted
to taste (add `-r`, `-t`, `-x`, etc.):

```sh
#!/bin/sh -e
if [ "$2" != -bsau ]; then
    exec gpg "$@"  # fallback GnuPG when not signing
fi
passphrase2pgp -S -a -u "$3"
printf '\n[GNUPG:] SIG_CREATED ' >&2
```

This does *just* enough to convince Git that passphrase2pgp is actually
GnuPG. Then tell Git to use it in place of GnuPG:

    $ git config gpg.program path/to/script

Example session of signing a tag with passphrase2pgp:

    $ git tag -s tagname -m 'Tag message'
    passphrase: 
    passphrase (repeat): 

Tag verification (via fallback to GnuPG):

    $ passphrase2pgp -u "..." -p | gpg --import
    passphrase: 
    passphrase (repeat): 
    $ git verify-tag tagname
    gpg: Good signature from ...

Unfortunately this configuration is fragile, but there's no practical
way to avoid it. The Git documentation says it depends on the GnuPG
interface without being specific, so the only robust solution is to
re-implement the entire GnuPG interface.

## Philosophy

Since [OpenPGP encryption is neither good nor useful anymore][mg], I
considered not generating an encryption subkey. The "privacy" portion of
OpenPGP has become the least important part.

OpenPGP digital signatures still have *some* limited use, mostly due to
momentum and lack of alternatives. The OpenPGP specification is
over-engineered, loaded with useless legacy cruft, and ambiguous in many
places. GnuPG is honestly not that great of an OpenPGP implementation,
and I have low confidence in it. I stubbed my toe on a number of minor
GnuPG bugs when hammering it with (usually invalid) output from
passphrase2pgp while it was being developed.

[mg]: https://blog.cryptographyengineering.com/2014/08/13/whats-matter-with-pgp/

## References

* [RFC 4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
* [RFC 6637: Elliptic Curve Cryptography (ECC) in OpenPGP](https://tools.ietf.org/html/rfc6637) (incomplete / inaccurate)
* [RFC 7748: Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
* [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
* [RFC Draft: EdDSA for OpenPGP](https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00)
* [RFC Draft: OpenPGP Message Format](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07) (incomplete / inaccurate)
