# Predictable, passphrase-based PGP key generator

passphrase2pgp generates, in OpenPGP format, an EdDSA signing key and
Curve25519 encryption subkey entirely from a passphrase, essentially
allowing you to [store a backup of your PGP keys in your brain][blog].
At any time you can re-run the tool and re-enter the passphrase to
reproduce the original keys.

The keys are derived from the passphrase and User ID (as salt) using
[Argon2id][argon2] (memory=1GB and time=8) and [RFC 8032][rfc8032]. It's
aggressive enough to protect from offline brute force attacks
passphrases short enough to be memorable by humans. Always use [a strong
passphrase][dw].

Requires Go 1.9 or later.

See also: [Long Key ID Collider][long]

[argon2]: https://github.com/P-H-C/phc-winner-argon2
[rfc8032]: https://tools.ietf.org/html/rfc8032
[dw]: https://en.wikipedia.org/wiki/Diceware
[blog]: https://nullprogram.com/blog/2019/07/10/
[long]: https://github.com/skeeto/pgpcollider

## Installation

    $ go get -u github.com/skeeto/passphrase2pgp

## Usage

Quick start: Provide a user ID (`-u`) and pipe the output into GnuPG.

    $ passphrase2pgp -u "Real Name <name@example.com>" | gpg --import

**Either `--uid` (`-u`) or `--load` (`-l`) is required.**

* The `--uid` (`-u`) option supplies the user ID string for the key to
  be generated. If `--uid` is missing, the `REALNAME` and `EMAIL`
  environmental variables are used to construct a user ID, but only if
  both are present.

* The `--load` (`-l`) option loads a previously generated key for use in
  other operations (signature creation, ASCII-armored public key, etc.).

There are three commands:

* Key generation (`--key`, `-K`) [default]: Writes a key to standard
  output. This is a secret key by default, but `--public` (`-p`)
  restricts it to a public key.

* Detached signatures (`--sign`, `-S`): Signs one or more input files.
  Unless `--load` is used, also generates a key, but that key is not
  output. If no files are given, signs standard input to standard
  output. Otherwise for each argument `file` creates `file.sig` with a
  detached signature. If armor is enabled (`--armor`, `-a`), the file is
  named `file.asc`.

* Cleartext signature (`--clearsign`, `-T`): Cleartext signs standard
  input to standard output, or from a file to standard output. The usual
  cleartext signature caveats apply.

Use `--help` (`-h`) for a full option listing:

```
Usage:
   passphrase2pgp <-u id|-l key> [-hv] [-c id] [-i pwfile] [--pinentry[=cmd]]
       -K [-anps] [-e[n]] [-f pgp|ssh] [-r n] [-t secs] [-x[spec]]
       -S [-a] [-r n] [files...]
       -T [-r n] >doc-signed.txt <doc.txt
Commands:
   -K, --key              output a key (default)
   -S, --sign             output detached signatures
   -T, --clearsign        output a cleartext signature
Options:
   -a, --armor            encode output in ASCII armor
   -c, --check KEYID      require last Key ID bytes to match
   -e, --protect[=ASKS]   protect private key with S2K
   -f, --format pgp|ssh   select key format [pgp]
   -h, --help             print this help message
   -i, --input FILE       read passphrase from file
   -l, --load FILE        load key from file instead of generating
   -n, --now              use current time as creation date
   --pinentry[=CMD]       use pinentry to read the passphrase
   -p, --public           only output the public key
   -r, --repeat N         number of repeated passphrase prompts
   -s, --subkey           also output an encryption subkey
   -t, --time SECONDS     key creation date (unix epoch seconds)
   -u, --uid USERID       user ID for the key
   -v, --verbose          print additional information
   --version              print version information
   -x, --expires[=SPEC]   set key expiration time [2y]
```

Per the OpenPGP specification, **the Key ID is a hash over both the key
and its creation date.** Therefore using a different date with the same
passphrase/ID will result in a different Key ID, despite the underlying
key being the same. For this reason, passphrase2pgp uses Unix epoch 0
(January 1, 1970) as the default creation date. You can override this
with `--time` (`-t`) or `--now` (`-n`), but, to regenerate the same key
in the future, you will need to use `--time` to reenter the exact time.
If 1970 is a problem, then choose another memorable date.

The `--check` (`-c`) causes passphrase2pgp to abort if the final bytes
of the Key ID do not match the hexadecimal argument. If this option is
not provided, the `KEYID` environment variable is used if available. In
either case, `--repeat` (`-r`) is set to zero unless it was explicitly
provided. The additional passphrase check is unnecessary if they Key ID
is being checked.

The `--protect` option uses OpenPGP's S2K feature to encrypt the private
key in the exported format. Rather than prompt for an S2K passphrase,
passphrase2pgp will reuse your derivation passphrase as the protection
passphrase. However, keep in mind that the S2K algorithm is *much*
weaker than the algorithm used to derive the asymmetric key, Argon2id.
Given an optional numeric argument, `--protect` will prompt that many
times (like `--repeat`) for a separate S2K passphrase.

By default keys are not given an expiration date and do not expire. To
retire a key, you would need to use another OpenPGP implementation to
import your key and generate a revocation certificate. Alternatively,
the `--expires` (`-x`) option sets an expiration date, defaulting to two
years from now. As an optional argument, it accepts a time specification
similar to GnuPG: days (d), weeks (w), months (m), and years (y). For
example, `--expires=10y` or `-x10y` sets the expiration date to 10 years
from now. Without a suffix, the value is interpreted as a specific unix
epoch timestamp.

Unfortunately there's a bug in the way GnuPG processes key expiration
dates that affect passphrase2pgp. Keys with a zero creation date are
[incorrectly considered never to expire][t4670] despite an explicit
expiration date. This means if you use passphrase2pgp's default creation
date, the `--expires` (`-x`) may *appear* not to work, and **GnuPG will
incorrectly verify signatures from your expired keys.** Further, GnuPG
[generally doesn't compute expiration dates correctly][T4669]. OpenPGP
allows expiration dates beyond the year 2106, and, unlike GnuPG,
passphrase2pgp will allow you construct such keys, but GnuPG will use an
incorrect (earlier) date.

[t4669]: https://dev.gnupg.org/T4669
[t4670]: https://dev.gnupg.org/T4670

### Examples

Generate a private key and send it to GnuPG (no protection passphrase):

    $ passphrase2pgp --uid "..." | gnupg --import

Or, with `--protect`, reuse the derivation passphrase as the protection
passphrase so that the key is encrypted on the GnuPG keyring using your
derivation passphrase:

    $ passphrase2pgp --protect --uid "..." | gnupg --import

Or to prompt (once) for a different passphrase to use as the protection
passphrase:

    $ passphrase2pgp --protect=1 --uid "..." | gnupg --import

Create an armored public key for publishing and sharing:

    $ passphrase2pgp --uid "..." --armor --public > Real-Name.asc

Since passing `--uid` every time you need it is tedious, that argument
can be supplied implicitly via two environment variables, `REALNAME` and
`EMAIL`. The remaining examples assume these variables are set.

    $ export REALNAME="Real Name"
    $ export EMAIL="name@example.com"
    $ passphrase2pgp -ap > Real-Name.asc

Create detached signatures (`-S`) for some files:

    $ passphrase2pgp -S document.txt avatar.jpg

This will create `document.txt.sig` and `avatar.jpg.sig`. The other end
would use GnuPG to verify the signatures like so:

    $ gpg --import Real-Name.asc
    $ gpg --verify document.txt.sig
    $ gpg --verify avatar.jpg.sig

Normally each command must derive keys from scratch from the passphrase,
requiring the user to re-enter it for each command and wait. To avoid
this, save the secret key to a file in OpenPGP format and then load
(`--load`) it for other commands. This will save an unprotected version:

    $ passphrase2pgp > secret.pgp

Then you can sign files without re-entering your passphrase:

    $ passphrase2pgp -S --load secret.pgp document.txt avatar.jpg

If you used an S2K protection passphrase (`--protect`), passphrase2pgp
will prompt for it when loading such keys.

More signatures, but ASCII-armored:

    $ passphrase2pgp -S -lsecret.pgp --armor document.txt avatar.jpg
    $ gpg --verify document.txt.asc
    $ gpg --verify avatar.jpg.asc

Create a cleartext-signed (`-T`) text document:

    $ passphrase2pgp -T >signed-doc.txt <doc.txt

### Intended Workflow

There are two usage patterns: "lite" and "full".

When a "lite" user sets up a new computer, they run passphrase2pgp just
once and send the key straight into GnuPG. After this they use GnuPG for
everything OpenPGP-related. This command installs the secret key in
GnuPG with a separate, more convenient, protection passphrase:

    $ passphrase2pgp -u '...' -e1 | gpg --import

This user will not need to backup their keyring since they can always
regenerate their key in the future. They're also free to destroy their
keyring at any moment, such as before their computer is accessed by
untrusted people (border agents, etc.).

A "full" user will use passphrase2pgp directly for signatures and will
never store the secret key permanently. They derive the key on demand
only when needed. To make this convenient, this users sets `REALNAME`,
`EMAIL`, and `KEYID` in their `.profile`. This means they never have to
supply `--uid`, and there's no passphrase confirmation prompt.

For example, supposed John Doe is a "full" user setting up for the first
time with the passphrase "boa trusted stew critics dispute asked naming
gyms". First he sets his user ID in his `.profile`:

    export REALNAME="John Doe"
    export EMAIL="john.doe@example.com"

Then he generates his public key and gets the fingerprint:

    $ passphrase2pgp --verbose --public >John-Doe.asc
    User ID: John Doe <john.doe@example.com>
    passphrase: 
    passphrase (repeat): 
    Key ID: C8A22A0535AF18BC83D7AE21406CC07F8DABE73B

He publishes `John-Doe.asc` and adds the fingerprint to his `.profile`:

    export KEYID=C8A22A0535AF18BC83D7AE21406CC07F8DABE73B

This is the actual key for that user ID and passphrase, so you can try
each of these commands yourself. Later if he, say, needs to clearsign a
message:

    $ echo The swallow flies at midnight >message.txt
    $ passphrase2pgp -T <message.txt
    passphrase: 
    -----BEGIN PGP SIGNED MESSAGE-----
    Hash: SHA256

    The swallow flies at midnight
    -----BEGIN PGP SIGNATURE-----

    wnUEARYIACcFAl1UG1gJEEBswH+Nq+c7FiEEyKIqBTWvGLyD164hQGzAf42r5zsA
    ADWqAP9KfoQm02q+AXE5brS9lNZ8LVjFs6CefMA4C/83Da7E4wD/QnYNyFmpmTOm
    B6w1UvDnxyD0ksjmyj6NDiRs25b20gk=
    =0gf5
    -----END PGP SIGNATURE-----

Again, this was all done without ever storing the secret key in the file
system, even in protected form.

### GnuPG Trust

Trust is stored external to keys, so imported keys are always initially
untrusted. You will likely want to mark your newly-imported primary key
as trusted. Or use the `--trusted-key` option in `gpg.conf`.

    $ gpg --edit-key "Real Name"
    gpg> trust

Similarly, to allow gpgv to verify your signatures, append your public
key to its trusted keyring:

    $ passphrase2pgp -p >> ~/.gnupg/trustedkeys.kbx

#### Signing Git tags and commits

It's even possible to use passphrase2pgp directly to sign your Git tags
and commits. Just configure `gpg.program` to passphrase2pgp:

    $ git config --global gpg.program passphrase2pgp

However, with this setting you will be unable to verify commits and
tags. To work around this problem, wrap passphrase2pgp in a script like
the following, with options adjusted to taste (add `--repeat`, `--time`,
etc.):

```sh
#!/bin/sh -e
if [ "$2" != -bsau ]; then
    exec gpg "$@"  # fallback GnuPG when not signing
fi
passphrase2pgp --sign --armor --uid "$3"
printf '\n[GNUPG:] SIG_CREATED ' >&2
```

Then set `gpg.program` to this script instead:

    $ git config --global gpg.program path/to/script

This does *just* enough to convince Git that passphrase2pgp is actually
GnuPG. Example session of signing a tag with passphrase2pgp:

    $ git tag -s tagname -m 'Tag message'
    passphrase: 
    passphrase (repeat): 

Tag verification (via script to fallback to GnuPG):

    $ passphrase2pgp -u "..." -p | gpg --import
    passphrase: 
    passphrase (repeat): 
    $ git verify-tag tagname
    gpg: Good signature from ...

## OpenSSH format

Despite the name, passphrase2pgp can output a key in OpenSSH format,
selected by `--format` (`-f`). Passphrase protection (bcrypt) is
supported. When using this format, the `--armor` (`-a`), `--now` (`-n`),
`--subkey` (`-s`), and `--time` (`-t`) options are ignored since they do
not apply. The user ID becomes the key comment and is still used as the
salt.

    $ passphrase2pgp --format ssh | (umask 077; tee id_ed25519)

This will be *exactly* the same key pair as when generating an OpenPGP
key. It's just written out in a different format. The public key will be
harmlessly appended to the private key, but it could also be regenerated
with `ssh-keygen`:

    $ ssh-keygen -y -f id_ed25519 > id_ed25519.pub

With the `--public` (`-p`) option, only the public key will be output.

You may want to add a protection key to the generated key, which, again,
can be done with `ssh-keygen`:

    $ ssh-keygen -p -f id_ed25519

**Generally you really *should* have a unique SSH key per host**, and
this sort of long-term key is both unnecessary and undesired. If you
loose access to that computer — theft, retirement, etc. — then you can
remove just that host's key as an authorized key without affecting other
hosts. In general, SSH keys need not and should not be backed up,
including in your brain.

However, there is at least one case where a long-term, important SSH key
could be useful. Suppose you have a vital, remote system with password
authentication disabled. If you loose access to all of the authorized
keys, you can no longer remotely log into that system. Correcting this
problem may require traveling to the computer's location or using some
inconvenient means to regain access.

Instead, you could use passphrase2pgp to generate an *emergency* SSH key
and install it as an authorized key on the remote host. *But* don't
actually store the private key anywhere and don't normally use this key!
When you're in a pinch, use passphrase2pgp to regenerate the emergency
key, recover your access, then immediately destroy the emergency key.

Setting up the emergency key ahead of time:

    $ passphrase2pgp -u emergency -f ssh -p > ~/.ssh/emergency.pub
    $ ssh-copy-id -f -i ~/.ssh/emergency.pub important.example.com

Later, when in dire straits, generate the private key, and use it to
install a non-emergency key as a new authorized key:

    $ (umask 077; passphrase2pgp -u emergency -f ssh > ~/.ssh/emergency)
    $ ssh-add ~/.ssh/emergency
    $ rm ~/.ssh/emergency
    $ ssh-copy-id -i ~/.ssh/id_ed25519 important.example.com

## Justification

Isn't generating a key from a passphrase foolish? If you can reproduce
your key from a passphrase, so can any one else!

In 2019, the fastest available implementation of Argon2id running on the
best available cloud hardware takes just over 6 seconds with
passphrase2pgp's default parameters. That's 6 seconds of a dedicated
single CPU core and 1GB of RAM for a single guess. This means that at
the current cloud computing rates it costs around US$50 to make 2^20 (~1
million) passphrase guesses.

A randomly-generated password of length 8 composed of the 95 printable
ASCII characters has ~52.6 bits of entropy. Therefore **it would cost
around US$ 158 *billion* to for just a 50% chance of cracking that
passphrase**. If your passphrase is generated by a random process, and
it's at least this long, it is not the weak point in this system.

## Regarding the encryption subkey

Since [OpenPGP encryption is neither good nor useful anymore][mg], I
considered not generating an encryption subkey. The "privacy" portion of
OpenPGP has become the least important part. However, the upcoming
update to OpenPGP, rfc4880bis, adds AEAD encryption, and this could make
encryption interesting again.

OpenPGP digital signatures still have *some* limited use, mostly due to
the lack of adoption of the alternatives. The OpenPGP specification is
too flexible and is loaded with legacy cruft. Further, GnuPG is honestly
not a great OpenPGP implementation, and I do not have high confidence in
it.

[mg]: https://blog.cryptographyengineering.com/2014/08/13/whats-matter-with-pgp/

## Roadmap

* AEAD (tag 20) encryption and limited decryption

## References

* [RFC 4880: OpenPGP Message Format](https://tools.ietf.org/html/rfc4880)
* [RFC 6637: Elliptic Curve Cryptography (ECC) in OpenPGP](https://tools.ietf.org/html/rfc6637) (incomplete / inaccurate)
* [RFC 7748: Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)
* [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/html/rfc8032)
* [RFC Draft: EdDSA for OpenPGP](https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00)
* [RFC Draft: OpenPGP Message Format](https://tools.ietf.org/html/draft-ietf-openpgp-rfc4880bis-07) (incomplete / inaccurate)
