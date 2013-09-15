/* http://tools.ietf.org/html/rfc4880
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>
#include <gcrypt.h>
#include <gmp.h>

typedef struct {
    char *buffer;
    size_t length;
} mpi_t;

char *hash_passphrase(char *input, size_t bits) {
    int i, blocks = bits % 512 == 0 ? bits / 512 : 1 + bits / 512;
    char *result = malloc(blocks * 64);
    gcry_md_hash_buffer(GCRY_MD_SHA512, result, input, strlen(input));
    for (i = 1; i < blocks; i++) {
        gcry_md_hash_buffer(GCRY_MD_SHA512, result + i * 64,
                            result + (i - 1) * 64, 64);
    }
    return result;
}

void totient(mpz_t rop, mpz_t p, mpz_t q) {
    mpz_t dp, dq;
    mpz_inits(dp, dq, NULL);
    mpz_sub_ui(dp, p, 1);
    mpz_sub_ui(dq, q, 1);
    mpz_mul(rop, dp, dq);
    mpz_clears(dp, dq, NULL);
}

int count_left_zeros(uint8_t u) {
    unsigned count = 0;
    while (u) {
        u >>= 1;
        count++;
    }
    return 8 - count;
}

mpi_t *openpgp_export(mpz_t n) {
    size_t raw_length;
    char *raw = mpz_export(NULL, &raw_length, 1, 1, 1, 0, n);
    mpi_t *mpi = malloc(sizeof(mpi_t));
    mpi->length = raw_length + 2;
    mpi->buffer = malloc(mpi->length);
    uint16_t header = raw_length * 8;  /* XXX */
    header -= count_left_zeros(raw[0]);
    header = htons(header);
    memcpy(mpi->buffer, &header, 2);
    memcpy(mpi->buffer + 2, raw, raw_length);
    free(raw);
    return mpi;
}

int main() {
    char *passphrase = "hello";
    int nbits = 2048, nbytes = nbits / 8;

    mpz_t p, q, n, e, d, t, u;
    mpz_inits(p, q, n, d, t, u, NULL);
    mpz_init_set_ui(e, 0x101);

    /* Generate p and q from the passphrase. */
    char *hash = hash_passphrase(passphrase, nbits);
    mpz_import(p, nbytes / 2, 1, 1, 1, 0, hash);
    mpz_sub_ui(p, p, 1);
    mpz_nextprime(p, p);
    mpz_import(q, nbytes / 2, 1, 1, 1, 0, hash + nbytes / 2);
    mpz_sub_ui(q, q, 1);
    mpz_nextprime(q, q);
    mpz_mul(n, p, q);

    /* Compute d and u. */
    totient(t, p, q);
    mpz_invert(d, e, t);
    mpz_invert(u, p, q);

    /* ensure p < q */
    if (mpz_cmp(p, q) > 0) {
        mpz_swap(p, q);
    }

    mpi_t *out[6];
    out[0] = openpgp_export(n);
    out[1] = openpgp_export(e);
    out[2] = openpgp_export(d);
    out[3] = openpgp_export(p);
    out[4] = openpgp_export(q);
    out[5] = openpgp_export(u);

    /* Compute secret checksum */
    size_t i, b = 0;
    uint16_t checksum = 0;
    for (i = 2; i < 6; i++) {
        for (b = 0; b < out[i]->length; b++) {
            checksum += out[i]->buffer[b];
        }
    }
    checksum = htons(checksum);

    /* Compute total packet size. */
    uint16_t total = 1 + 4 + 1; /* public header */
    total += 1 + 2; /* secret header */
    for (i = 0; i < 6; i++) {
        total += out[i]->length;
    }
    total = htons(total);

    fputc(0x95, stdout); /* PTag (old format), two-octet length header */
    fwrite(&total, 2, 1, stdout); /* packet length */
    fputc(0x04, stdout); /* Packet version (4) */
    uint32_t seconds = time(NULL);
    seconds = htonl(seconds);
    fwrite(&seconds, 4, 1, stdout); /* current time */
    fputc(0x01, stdout); /* Algo (1) */
    for (i = 0; i < 2; i++) {
        /* Public key parts */
        fwrite(out[i]->buffer, out[i]->length, 1, stdout);
    }
    putc(0x00, stdout); /* Not encrypted. */
    for (i = 2; i < 6; i++) {
        /* Private key parts */
        fwrite(out[i]->buffer, out[i]->length, 1, stdout);
    }
    fwrite(&checksum, 2, 1, stdout); /* Checksum */

    return EXIT_SUCCESS;
}
