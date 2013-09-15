# Predictable PGP key generation

The purpose of this tool is to generate RSA keys from a passphrase and
output them in the [OpenPGP format](http://tools.ietf.org/html/rfc4880)
to be imported into your own PGP software (GnuPG, etc). The purpose is
to allow PGP keys to be stored entirely in a human brain, like a Bitcoin
brain wallet.

I have no idea if this is a good idea or not. Can a reasonably
human-memorable passphrase have enough entropy for a 2048-bit RSA key?
Use at your own risk!

## Status

It outputs a valid secret key packet and user ID packet, but no
signature packet to bind them together, so GnuPG refuses to import it.
Once the signature packet is in place I think it should be ready for
use.

## Hash algorithm

I'm using a totally amateur algorithm for deriving a 2048-bit RSA key
from a passphrase. The PRNG looks like this:

 * Compute the SHA-512 hash of the passphrase to generate a 512-bit block.
 * For each additional 512 block of bits needed, compute the SHA-512
   hash of the previously generated block.

In Emacs Lisp, it looks like this:

```el
(defun hash-passphrase (passphrase bits)
  (cl-loop for chunk = (secure-hash 'sha512 passphrase nil nil :binary)
           then (secure-hash 'sha512 chunk nil nil :binary)
           collect chunk into chunks
           while (> (cl-decf bits 512) 0)
           finally (cl-return (apply #'concat chunks))))
```

For the actual key, generate 1024 bits for pre-p and another 1024 bits
for pre-q, most-significant bit first. For both pre-p and pre-q,
increment until the first prime number is found, calling them p and q.
Then compute the rest of the RSA key from p and q.

Currently missing is some sort of key stretching.
