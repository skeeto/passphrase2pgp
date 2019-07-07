# Predictable, passphrase-based PGP key generator

passphrase2pgp generates an EdDSA OpenPGP key entirely from a
passphrase, essentially allowing you to store a backup of your PGP key
in your brain. At any time you can re-run the tool and re-enter the
passphrase to reproduce the original key.

The key is derived from the passphrase using [Argon2id][argon2]
(memory=1GB and time=8) and [RFC 8032][rfc8032]. It's aggressive enough
to protect passphrases short enough to be memorable by humans from
offline brute force attacks. Always use [a strong passphrase][dw].

passphrase2pgp only generates an EdDSA (e.g. sign only) primary key. The
primary key is not encrypted (no string-to-key), and no subkeys are
generated. The intended purpose is to recover, without backups, a
cryptographic identity, not necessarily encryption keys.

[argon2]: https://github.com/P-H-C/phc-winner-argon2
[rfc8032]: https://tools.ietf.org/html/rfc8032
[dw]: https://en.wikipedia.org/wiki/Diceware

## Installation

    $ go get -u github.com/skeeto/passphrase2pgp

## Usage

Just pipe the output straight into GnuPG:

    $ passphrase2pgp -uid "Real Name <name@example.com>" | gpg --import

**The `-uid` argument is required.** Use `-help` for an option listing:

    Usage of passphrase2pgp:
      -date int
        	creation date (unix epoch seconds)
      -now
        	use current time as creation date
      -paranoid
        	paranoid mode
      -repeat uint
        	number of repeated passphrase prompts (default 1)
      -uid string
        	key user ID (required)

**The Key ID is a hash over both the key and its creation date.**
Therefore using a different date with the same passphrase will result in
a different key. For this reason, passphrase2pgp uses Unix epoch 0
(January 1, 1970) as the default creation date. You can override this
with `-date` or `-now`, but, to regenerate the same key in the future,
you will need to use `-date` to reenter the exact time. If 1970 is a
problem, then choose another memorable date.

The `-paranoid` setting quadruples the KDF difficulty. This will result
in a different key for the same passphrase.

Once your key is generated, you may want to secure it with a protection
passphrase on your GnuPG keychain in order to protect it at rest:

    $ gpg --edit-key "Real Name"
    gpg> passwd

If you want to use GnuPG for encryption, create an encryption subkey
associated with your passphrase-backed identity:

    $ gpg --expert --edit-key "Real Name"
    gpg> addkey
    Please select what kind of key you want:
       (3) DSA (sign only)
       (4) RSA (sign only)
       (5) Elgamal (encrypt only)
       (6) RSA (encrypt only)
       (7) DSA (set your own capabilities)
       (8) RSA (set your own capabilities)
      (10) ECC (sign only)
      (11) ECC (set your own capabilities)
      (12) ECC (encrypt only)
      (13) Existing key
    Your selection? 12
    Please select which elliptic curve you want:
       (1) Curve 25519
       (3) NIST P-256
       (4) NIST P-384
       (5) NIST P-521
       (6) Brainpool P-256
       (7) Brainpool P-384
       (8) Brainpool P-512
       (9) secp256k1
    Your selection? 1
    Please specify how long the key should be valid.
             0 = key does not expire
          <n>  = key expires in n days
          <n>w = key expires in n weeks
          <n>m = key expires in n months
          <n>y = key expires in n years
    Key is valid for? (0)
    Key does not expire at all
    Is this correct? (y/N) y
    Really create? (y/N) y

Warning: **You will not be able to recover subkeys since they are not
derived from the passphrase.**

## Roadmap

Perhaps passphrase2pgp should also generate an encryption subkey (Curve
25519) at the same time? This would allow subkeys to be recovered as
well. However, [OpenPGP encryption is neither good nor useful
anymore][mg], and I'd prefer not to encourage its use.

OpenPGP signatures still have *some* limited use, mostly due to momentum
and lack of alternatives. The OpenPGP specification is over-engineered,
loaded with useless legacy cruft, and ambiguous in many places. GnuPG is
honestly not that great of an OpenPGP implementation, and I have low
confidence in it. I stubbed my toe on a number of minor GnuPG bugs when
hammering it with (usually invalid) output from passphrase2pgp while it
was being developed.

[mg]: https://blog.cryptographyengineering.com/2014/08/13/whats-matter-with-pgp/

## References

* [RFC 4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
* [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
* [RFC Draft: EdDSA for OpenPGP](https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00)
