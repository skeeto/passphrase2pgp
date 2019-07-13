# Predictable, passphrase-based PGP key generator

passphrase2pgp generates, in OpenPGP format, an EdDSA signing key and
Curve25519 encryption subkey entirely from a passphrase, essentially
allowing you to store a backup of your PGP keys in your brain. At any
time you can re-run the tool and re-enter the passphrase to reproduce
the original keys.

The keys are derived from the passphrase and User ID (as salt) using
[Argon2id][argon2] (memory=1GB and time=8) and [RFC 8032][rfc8032]. It's
aggressive enough to protect passphrases short enough to be memorable by
humans from offline brute force attacks. Always use [a strong
passphrase][dw].

Requires Go 1.9 or later.

[argon2]: https://github.com/P-H-C/phc-winner-argon2
[rfc8032]: https://tools.ietf.org/html/rfc8032
[dw]: https://en.wikipedia.org/wiki/Diceware

## Installation

    $ go get -u github.com/skeeto/passphrase2pgp

## Usage

Just pipe the output straight into GnuPG:

    $ passphrase2pgp -u "Real Name <name@example.com>" | gpg --import

**Either `-u` or `-l` is required.** The `-u` argument is used during
key generation, so to reproduce the same key you will need to use
exactly the same passphrase *and* User ID.

There are two modes of operation: key generation (`-K`, default) and
detached signatures (`-S`).

Use `-h` for an option listing:

    Usage of ./passphrase2pgp:
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
passphrase/uid will result in a different Key ID, despite the underlying
key being the same. For this reason, passphrase2pgp uses Unix epoch 0
(January 1, 1970) as the default creation date. You can override this
with `-date` or `-now`, but, to regenerate the same key in the future,
you will need to use `-date` to reenter the exact time. If 1970 is a
problem, then choose another memorable date.

The `-x` (paranoid) setting quadruples the KDF difficulty. This will
result in a different key for the same passphrase.

Once your key is generated, you may want to secure it with a protection
passphrase on your GnuPG keychain in order to protect it at rest:

    $ gpg --edit-key "Real Name"
    gpg> passwd

Trust is stored external to the keys, so imported keys are always
initially untrusted. You will likely want to mark your newly-imported
primary key as trusted.

    $ gpg --edit-key "Real Name"
    gpg> trust

The "sign" mode (`-S`) creates detached signatures:

    $ passphrase2pgp -S -u "Real Name <name@example.com>" <data >data.sig
    passphrase:
    passphrase (repeat):

To perform multiple operations at once without regenerating the key for
each operation, the load (`-l`) option exists to load a previously
generated key:

    $ passphrase2pgp -u "Real Name <name@example.com>" >secret.pgp
    passphrase:
    passphrase (repeat):
    $ passphrase2pgp -l secret.pgp -a -p >Real-Name.asc
    $ passphrase2pgp -S -l secret.pgp <data >data.sig

Where `Real-Name.asc`, `data`, and `data.sig` are distributed to others.
Consuming these in GnuPG:

    $ gpg --import Real-Name.asc
    $ gpg --verify data.sig

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
