#include <iostream>

#define ZPL_IMPLEMENTATION
#include "zpl/zpl.h"

#include "argon2/argon2.h"
#include "cppcrypto/hmac.h"
#include "cppcrypto/kalyna.h"
#include "cppcrypto/skein512.h"
#include "cppcrypto/threefish.h"
#include "randombytes/randombytes.h"

const unsigned int T3F_TWEAK_LEN = 16;
const unsigned int T3F_KEY_LEN = 128;
const unsigned int T3F_BLOCK_LEN = 128;
const unsigned int T3F_IV_LEN = 128;
const unsigned int NUM_BLOCKS = 2048;
const unsigned int CHUNK_LEN = NUM_BLOCKS * T3F_BLOCK_LEN;

const unsigned int MASTER_KEY_LEN = 256;
const unsigned int SALT_LEN = 64;
const unsigned int HEADER_LEN = 6;

const unsigned int KALYNA_KEY_LEN = 64;
const unsigned int KALYNA_IV_LEN = 64;
const unsigned int KALYNA_BLOCK_LEN = 64;

const unsigned int HMAC_KEY_LEN = 64;
const unsigned int HMAC_HASH_LEN = 64;
const unsigned int ENC_KEY_LEN = T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN +
                                 KALYNA_KEY_LEN + KALYNA_IV_LEN + HMAC_KEY_LEN;

const unsigned char header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

const uint32_t T = 9;
const uint32_t M = 1 << 19;
const uint32_t P = 1;

void check_fatal_err(bool cond, const char *msg) {
    if (cond) {
        fprintf(stderr, "Error: %s\n", msg);
        exit(EXIT_FAILURE);
    }
}

void *t3fc_malloc(size_t s) {
    void *buf = malloc(s);
    check_fatal_err(buf == NULL, "cannot allocate memory.");
    return buf;
}

int sodium_pad(size_t *padded_buflen_p, unsigned char *buf,
               size_t unpadded_buflen, size_t blocksize, size_t max_buflen) {
    unsigned char *tail;
    size_t i;
    size_t xpadlen;
    size_t xpadded_len;
    volatile unsigned char mask;
    unsigned char barrier_mask;

    if (blocksize <= 0U) {
        return -1;
    }
    xpadlen = blocksize - 1U;
    if ((blocksize & (blocksize - 1U)) == 0U) {
        xpadlen -= unpadded_buflen & (blocksize - 1U);
    } else {
        xpadlen -= unpadded_buflen % blocksize;
    }

    check_fatal_err((size_t)SIZE_MAX - unpadded_buflen <= xpadlen,
                    "cannot add padding.");

    xpadded_len = unpadded_buflen + xpadlen;
    if (xpadded_len >= max_buflen) {
        return -1;
    }
    tail = &buf[xpadded_len];
    if (padded_buflen_p != NULL) {
        *padded_buflen_p = xpadded_len + 1U;
    }
    mask = 0U;
    for (i = 0; i < blocksize; i++) {
        barrier_mask = (unsigned char)(((i ^ xpadlen) - 1U) >>
                                       ((sizeof(size_t) - 1) * CHAR_BIT));
        *(tail - i) = ((*(tail - i)) & mask) | (0x80 & barrier_mask);
        mask |= barrier_mask;
    }
    return 0;
}

int sodium_unpad(size_t *unpadded_buflen_p, const unsigned char *buf,
                 size_t padded_buflen, size_t blocksize) {
    const unsigned char *tail;
    unsigned char acc = 0U;
    unsigned char c;
    unsigned char valid = 0U;
    volatile size_t pad_len = 0U;
    size_t i;
    size_t is_barrier;

    if (padded_buflen < blocksize || blocksize <= 0U) {
        return -1;
    }
    tail = &buf[padded_buflen - 1U];

    for (i = 0U; i < blocksize; i++) {
        c = *(tail - i);
        is_barrier =
            (((acc - 1U) & (pad_len - 1U) & ((c ^ 0x80) - 1U)) >> 8) & 1U;
        acc |= c;
        pad_len |= i & (1U + ~is_barrier);
        valid |= (unsigned char)is_barrier;
    }
    *unpadded_buflen_p = padded_buflen - 1U - pad_len;

    return (int)(valid - 1U);
}

void get_master_key(const char *path, unsigned char *master_key) {
    zpl_file keyfile = {0};
    zplFileError file_rc = zpl_file_open(&keyfile, path);
    check_fatal_err(file_rc != ZPL_FILE_ERROR_NONE, "cannot open file.");
    i64 file_size = zpl_file_size(&keyfile);
    check_fatal_err(file_size != MASTER_KEY_LEN,
                    "key file must have exactly 256 bytes.");
    b32 b_rc = zpl_file_read(&keyfile, master_key, MASTER_KEY_LEN);
    check_fatal_err(!b_rc, "cannot read file.");
    zpl_file_close(&keyfile);
}

void encrypt(zpl_file *in_file, zpl_file *out_file, unsigned char *master_key);
void t3f_encrypt_chunk(cppcrypto::threefish1024_1024 &t3f,
                       unsigned char *t3f_iv, unsigned char *chunk,
                       size_t chunk_len);
void kl_encrypt_chunk(cppcrypto::kalyna512_512 &kl, unsigned char *kl_iv,
                      unsigned char *chunk, size_t chunk_len);
void decrypt(zpl_file *in_file, zpl_file *out_file, unsigned char *master_key);
void make_key(unsigned char *master_key, unsigned char *enc_key,
              unsigned char *salt);

int main(int argc, char **argv) {

    unsigned char master_key[MASTER_KEY_LEN];
    try {
        if (argc == 3 && strcmp(argv[1], "-kf") == 0) {
            randombytes(master_key, MASTER_KEY_LEN);
            zpl_file keyfile = {0};
            zplFileError file_rc = zpl_file_create(&keyfile, argv[2]);
            check_fatal_err(file_rc != ZPL_FILE_ERROR_NONE,
                            "cannot open file.");
            b32 b_rc = zpl_file_write(&keyfile, master_key, MASTER_KEY_LEN);
            check_fatal_err(!b_rc, "cannot write file.");
            zpl_file_close(&keyfile);

        } else if (argc == 8 &&
                   (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
                   strcmp(argv[6], "-o") == 0) {

            if (zpl_file_exists(argv[7])) {
                std::string yn;
                do {
                    std::cout << "File exists. Do you want to overwrite? (y/n) "
                              << std::flush;
                    std::cin >> yn;
                } while (yn != "n" && yn != "N" && yn != "y" && yn != "Y");
                if (yn == "n" || yn == "N") {
                    std::cout << "Please choose a different output file."
                              << std::endl;
                    return EXIT_SUCCESS;
                }
            }

            get_master_key(argv[3], master_key);
            zpl_file in_file = {0};
            zplFileError file_rc = zpl_file_open(&in_file, argv[5]);
            check_fatal_err(file_rc != ZPL_FILE_ERROR_NONE,
                            "cannot open file.");
            zpl_file out_file = {0};
            file_rc = zpl_file_create(&out_file, argv[7]);
            check_fatal_err(file_rc != ZPL_FILE_ERROR_NONE,
                            "cannot create file.");
            if (strcmp(argv[1], "-e") == 0) {
                encrypt(&in_file, &out_file, master_key);
            } else if (strcmp(argv[1], "-d") == 0) {
                decrypt(&in_file, &out_file, master_key);
            }
            zpl_file_close(&in_file);
            zpl_file_close(&out_file);

        } else {
            check_fatal_err(true, "unknown options.");
        }
    } catch (std::exception const &ex) {
        std::cerr << "caught: " << ex.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

void encrypt(zpl_file *in_file, zpl_file *out_file, unsigned char *master_key) {

    b32 b_rc = zpl_file_write(out_file, header, HEADER_LEN);
    check_fatal_err(!b_rc, "cannot write header.");
    unsigned char salt[SALT_LEN];
    randombytes(salt, SALT_LEN);
    b_rc = zpl_file_write(out_file, salt, SALT_LEN);
    check_fatal_err(!b_rc, "cannot write header.");

    unsigned char enc_key[ENC_KEY_LEN];
    make_key(master_key, enc_key, salt);

    f64 now = zpl_time_now();
    cppcrypto::threefish1024_1024 t3f;
    t3f.init((const unsigned char *)enc_key,
             cppcrypto::block_cipher::encryption);
    t3f.set_tweak((const unsigned char *)&enc_key[T3F_KEY_LEN]);
    cppcrypto::kalyna512_512 kl;
    kl.init((const unsigned char
                 *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN],
            cppcrypto::block_cipher::encryption);
    cppcrypto::hmac hmac(cppcrypto::skein512(512),
                         &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN +
                                  KALYNA_KEY_LEN + KALYNA_IV_LEN],
                         HMAC_KEY_LEN);
    hmac.update(header, HEADER_LEN);
    hmac.update(salt, SALT_LEN);

    unsigned char t3f_iv[ENC_KEY_LEN];
    unsigned char kl_iv[KALYNA_IV_LEN];
    memcpy(t3f_iv, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN], T3F_IV_LEN);
    memcpy(kl_iv,
           &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KALYNA_KEY_LEN],
           KALYNA_IV_LEN);
    unsigned char *chunk = (unsigned char *)t3fc_malloc(CHUNK_LEN);
    size_t chunk_len = CHUNK_LEN;
    size_t padded_len = 0;
    i64 in_file_size = zpl_file_size(in_file);
    while (in_file_size > 0) {
        b_rc = zpl_file_read(in_file, chunk, CHUNK_LEN);
        check_fatal_err(!b_rc, "cannot read file.");
        if (in_file_size < CHUNK_LEN) {
            check_fatal_err(sodium_pad(&padded_len, chunk, in_file_size,
                                       T3F_BLOCK_LEN, CHUNK_LEN) != 0,
                            "buffer is not large enough.");
            chunk_len = padded_len;
        }
        t3f_encrypt_chunk(t3f, t3f_iv, chunk, chunk_len);
        kl_encrypt_chunk(kl, kl_iv, chunk, chunk_len);
        hmac.update(chunk, chunk_len);
        b_rc = zpl_file_write(out_file, chunk, chunk_len);
        check_fatal_err(!b_rc, "cannot write file.");
        in_file_size -= CHUNK_LEN;
    }

    unsigned char hmac_hash[HMAC_HASH_LEN];
    hmac.final(hmac_hash);
    b_rc = zpl_file_write(out_file, hmac_hash, HMAC_HASH_LEN);
    check_fatal_err(!b_rc, "cannot write file.");

    free(chunk);
    f64 duration = zpl_time_now() - now;
    std::cout << "encrypt " << duration << std::endl;
}

void t3f_encrypt_chunk(cppcrypto::threefish1024_1024 &t3f,
                       unsigned char *t3f_iv, unsigned char *chunk,
                       size_t chunk_len) {
    uint32_t i = 0;
    for (; chunk_len >= T3F_BLOCK_LEN; ++i, chunk_len -= T3F_BLOCK_LEN) {
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] =
                t3f_iv[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        t3f.encrypt_block(&chunk[i * T3F_BLOCK_LEN], &chunk[i * T3F_BLOCK_LEN]);
        memcpy(t3f_iv, &chunk[i * T3F_BLOCK_LEN], T3F_BLOCK_LEN);
    }
    check_fatal_err(
        chunk_len != 0,
        "plaintext must be a multiple of the block size (128 bytes).");
}

void kl_encrypt_chunk(cppcrypto::kalyna512_512 &kl, unsigned char *kl_iv,
                      unsigned char *chunk, size_t chunk_len) {
    uint32_t i = 0;
    for (; chunk_len >= KALYNA_BLOCK_LEN; ++i, chunk_len -= KALYNA_BLOCK_LEN) {
        for (uint32_t j = 0; j < KALYNA_BLOCK_LEN; ++j) {
            chunk[i * KALYNA_BLOCK_LEN + j] =
                kl_iv[j] ^ chunk[i * KALYNA_BLOCK_LEN + j];
        }
        kl.encrypt_block(&chunk[i * KALYNA_BLOCK_LEN],
                         &chunk[i * KALYNA_BLOCK_LEN]);
        memcpy(kl_iv, &chunk[i * KALYNA_BLOCK_LEN], KALYNA_BLOCK_LEN);
    }
    check_fatal_err(
        chunk_len != 0,
        "plaintext must be a multiple of the block size (64 bytes).");
}

void decrypt(zpl_file *in_file, zpl_file *out_file, unsigned char *master_key) {
}

void make_key(unsigned char *master_key, unsigned char *enc_key,
              unsigned char *salt) {
    f64 now = zpl_time_now();
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt,
                                      SALT_LEN, enc_key,
                                      ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");
    f64 duration = zpl_time_now() - now;
    std::cout << "argon2  " << duration << std::endl;
}