#include <iostream>

#include <cryptopp/hrtimer.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/misc.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>

#define STB_LIB_IMPLEMENTATION
#include "stb/stb_lib.h"

#include "argon2/argon2.h"
#include "randombytes/randombytes.h"

const unsigned int T3F_TWEAK_LEN = 16;
const unsigned int T3F_KEY_LEN = 128;
const unsigned int T3F_BLOCK_LEN = 128;
const unsigned int T3F_IV_LEN = 128;
const unsigned int NUM_BLOCKS = 2;
const unsigned int CHUNK_LEN = NUM_BLOCKS * T3F_BLOCK_LEN;

const unsigned int MASTER_KEY_LEN = 256;
const unsigned int SALT_LEN = 64;
const unsigned int HEADER_LEN = 6;

const unsigned int KL_KEY_LEN = 64;
const unsigned int KL_IV_LEN = 64;
const unsigned int KL_BLOCK_LEN = 64;

const unsigned int HMAC_KEY_LEN = 64;
const unsigned int HMAC_HASH_LEN = 64;
const unsigned int ENC_KEY_LEN = T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN +
                                 KL_KEY_LEN + KL_IV_LEN + HMAC_KEY_LEN;

const unsigned char header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

const uint32_t T = 3;
const uint32_t M = 1 << 10;
const uint32_t P = 1;

void check_fatal_err(bool cond, const char *msg) {
    if (cond) {
        fprintf(stderr, "Error: %s\n", msg);
        exit(EXIT_FAILURE);
    }
}

FILE *t3fc_fopen(const char *path, const char *flags) {
    FILE *f = stb__fopen(path, flags);
    check_fatal_err(f == NULL, "cannot open file.");
    return f;
}

void get_master_key(const char *keyfile, unsigned char *master_key) {
    FILE *f = t3fc_fopen(keyfile, "rb");
    check_fatal_err(stb_filelen(f) != MASTER_KEY_LEN,
                    "keyfile must have exactly 256 bytes.");
    check_fatal_err(fread(master_key, 1, MASTER_KEY_LEN, f) != MASTER_KEY_LEN,
                    "cannot read key from file.");
    fclose(f);
}

void encrypt(FILE *input, FILE *output, unsigned char *master_key);
void t3f_encrypt_chunk(CryptoPP::Threefish1024::Encryption &t3f, unsigned char *chunk, size_t chunk_len, unsigned char *t3f_iv);
void kl_encrypt_chunk(CryptoPP::Kalyna512::Encryption &kl, unsigned char *chunk, size_t chunk_len, unsigned char *kl_iv);
void decrypt(FILE *input, FILE *output, unsigned char *master_key);
void t3f_decrypt_chunk(CryptoPP::Threefish1024::Encryption &t3f_enc, CryptoPP::Threefish1024::Decryption &t3f_dec, unsigned char *chunk, size_t chunk_len, unsigned char *t3f_iv);
void kl_decrypt_chunk(CryptoPP::Kalyna512::Encryption &kl_enc, CryptoPP::Kalyna512::Decryption &kl_dec, unsigned char *chunk, size_t chunk_len, unsigned char *kl_iv);
void make_key(unsigned char *master_key, unsigned char *enc_key, unsigned char *salt);

int main(int argc, char **argv) {

    CryptoPP::SecByteBlock master_key(MASTER_KEY_LEN);
    try {
        if (argc == 3 && strcmp(argv[1], "-kf") == 0) {
            randombytes(master_key, MASTER_KEY_LEN);
            FILE *master_key_file = t3fc_fopen(argv[2], "wb");
            check_fatal_err(fwrite(master_key, 1, MASTER_KEY_LEN, master_key_file) != MASTER_KEY_LEN, "cannot write master key to file.");
            fclose(master_key_file);

        } else if (argc == 8 &&
                   (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
                   strcmp(argv[6], "-o") == 0) {

            if (stb_fexists(argv[7])) {
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
            FILE *input = t3fc_fopen(argv[5], "rb");
            FILE *output = t3fc_fopen(argv[7], "wb");
            if (strcmp(argv[1], "-e") == 0) {
                encrypt(input, output, master_key);
            } else if (strcmp(argv[1], "-d") == 0) {
                decrypt(input, output, master_key);
            }
            fclose(input);
            fclose(output);

        } else {
            check_fatal_err(true, "unknown options.");
        }
    } catch (std::exception const &ex) {
        std::cerr << "caught: " << ex.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    return EXIT_SUCCESS;
}

void encrypt(FILE *input, FILE *output, unsigned char *master_key) {

    check_fatal_err(fwrite(header, 1, HEADER_LEN, output) != HEADER_LEN, "cannot write header.");
    unsigned char salt[SALT_LEN];
    randombytes(salt, SALT_LEN);
    check_fatal_err(fwrite(salt, 1, SALT_LEN, output) != SALT_LEN, "cannot write salt.");

    CryptoPP::SecByteBlock enc_key(ENC_KEY_LEN);
    make_key(master_key, enc_key, salt);

    CryptoPP::Timer timer;
    timer.StartTimer();
    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN], T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters t3f_params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(t3f_params);
    CryptoPP::Kalyna512::Encryption kl(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN], KL_KEY_LEN);
    CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN + KL_IV_LEN], HMAC_KEY_LEN);
    hmac.Update(header, HEADER_LEN);
    hmac.Update(salt, SALT_LEN);

    CryptoPP::SecByteBlock chunk(CHUNK_LEN);
    size_t chunk_len = 0;
    CryptoPP::SecByteBlock t3f_iv(T3F_IV_LEN);
    CryptoPP::SecByteBlock kl_iv(KL_IV_LEN);
    memcpy(t3f_iv.data(), &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN], T3F_IV_LEN);
    memcpy(kl_iv.data(), &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN], KL_IV_LEN);
    while ((chunk_len = fread(chunk, 1, CHUNK_LEN, input)) > 0) {
        check_fatal_err(chunk_len != CHUNK_LEN && ferror(input), "cannot read input.");
        t3f_encrypt_chunk(t3f, chunk, chunk_len, t3f_iv);
        kl_encrypt_chunk(kl, chunk, chunk_len, kl_iv);
        hmac.Update(chunk, chunk_len);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len, "cannot write to file.");
    }
    unsigned char hash[HMAC_HASH_LEN];
    hmac.Final(hash);
    check_fatal_err(fwrite(hash, 1, HMAC_HASH_LEN, output) != HMAC_HASH_LEN, "cannot write HMAC.");

    std::cout << "encrypt " << timer.ElapsedTimeAsDouble() << std::endl;
}

void t3f_encrypt(CryptoPP::Threefish1024::Encryption &t3f, unsigned char *chunk, size_t chunk_len, unsigned char *t3f_iv) {
    uint32_t i = 0;
    for (; chunk_len >= T3F_BLOCK_LEN; ++i, chunk_len -= T3F_BLOCK_LEN) {
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] = t3f_iv[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        t3f.ProcessBlock(&chunk[i * T3F_BLOCK_LEN], &chunk[i * T3F_BLOCK_LEN]);
        memcpy(t3f_iv, &chunk[i * T3F_BLOCK_LEN], T3F_BLOCK_LEN);
    }
    check_fatal_err(chunk_len != 0, "plaintext must be a multiple of the block size (128 bytes).");
}
void t3f_encrypt_chunk(CryptoPP::Threefish1024::Encryption &t3f, unsigned char *chunk, size_t chunk_len, unsigned char *t3f_iv) {
    size_t tail = chunk_len % T3F_BLOCK_LEN;
    if (tail == 0) {
        t3f_encrypt(t3f, chunk, chunk_len, t3f_iv);
    } else {
        if (chunk_len <= T3F_BLOCK_LEN) {
            t3f.ProcessBlock(t3f_iv, t3f_iv);
            for (uint32_t j = 0; j < chunk_len; ++j) {
                chunk[j] = t3f_iv[j] ^ chunk[j];
            }
        } else {
            size_t new_chunk_len = chunk_len + T3F_BLOCK_LEN - tail;
            memset(&chunk[chunk_len], 0, T3F_BLOCK_LEN - tail);
            unsigned char tmp[T3F_BLOCK_LEN];
            t3f_encrypt(t3f, chunk, new_chunk_len, t3f_iv);
            memcpy(tmp, &chunk[chunk_len - tail], T3F_BLOCK_LEN);
            memcpy(&chunk[chunk_len - tail], &chunk[chunk_len - T3F_BLOCK_LEN - tail], T3F_BLOCK_LEN);
            memcpy(&chunk[chunk_len - T3F_BLOCK_LEN - tail], tmp, T3F_BLOCK_LEN);
        }
    }
}
void kl_encrypt(CryptoPP::Kalyna512::Encryption &kl, unsigned char *chunk, size_t chunk_len, unsigned char *kl_iv) {
    uint32_t i = 0;
    for (; chunk_len >= KL_BLOCK_LEN; ++i, chunk_len -= KL_BLOCK_LEN) {
        for (uint32_t j = 0; j < KL_BLOCK_LEN; ++j) {
            chunk[i * KL_BLOCK_LEN + j] = kl_iv[j] ^ chunk[i * KL_BLOCK_LEN + j];
        }
        kl.ProcessBlock(&chunk[i * KL_BLOCK_LEN], &chunk[i * KL_BLOCK_LEN]);
        memcpy(kl_iv, &chunk[i * KL_BLOCK_LEN], KL_BLOCK_LEN);
    }
    check_fatal_err(chunk_len != 0, "plaintext must be a multiple of the block size (64 bytes).");
}
void kl_encrypt_chunk(CryptoPP::Kalyna512::Encryption &kl, unsigned char *chunk, size_t chunk_len, unsigned char *kl_iv) {
    size_t tail = chunk_len % KL_BLOCK_LEN;
    if (tail == 0) {
        kl_encrypt(kl, chunk, chunk_len, kl_iv);
    } else {
        if (chunk_len <= KL_BLOCK_LEN) {
            kl.ProcessBlock(kl_iv, kl_iv);
            for (uint32_t j = 0; j < chunk_len; ++j) {
                chunk[j] = kl_iv[j] ^ chunk[j];
            }
        } else {
            size_t new_chunk_len = chunk_len + KL_BLOCK_LEN - tail;
            memset(&chunk[chunk_len], 0, KL_BLOCK_LEN - tail);
            kl_encrypt(kl, chunk, new_chunk_len, kl_iv);
            unsigned char tmp[KL_BLOCK_LEN];
            memcpy(tmp, &chunk[chunk_len - tail], KL_BLOCK_LEN);
            memcpy(&chunk[chunk_len - tail], &chunk[chunk_len - KL_BLOCK_LEN - tail], KL_BLOCK_LEN);
            memcpy(&chunk[chunk_len - KL_BLOCK_LEN - tail], tmp, KL_BLOCK_LEN);
        }
    }
}

void decrypt(FILE *input, FILE *output, unsigned char *master_key) {
    
    unsigned char in_header[HEADER_LEN];
    check_fatal_err(fread(in_header, 1, HEADER_LEN, input) != HEADER_LEN, "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0, "wrong header.");
    unsigned char salt[SALT_LEN];
    check_fatal_err(fread(salt, 1, SALT_LEN, input) != SALT_LEN, "cannot read salt.");
                    
    CryptoPP::SecByteBlock enc_key(ENC_KEY_LEN);
    make_key(master_key, enc_key, salt);
    
    CryptoPP::Timer timer;
    timer.StartTimer();
    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN], T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters t3f_params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Decryption t3f_dec(enc_key, T3F_KEY_LEN);
    t3f_dec.SetTweak(t3f_params);
    CryptoPP::Threefish1024::Encryption t3f_enc(enc_key, T3F_KEY_LEN);
    t3f_enc.SetTweak(t3f_params);
    CryptoPP::Kalyna512::Decryption kl_dec(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN], KL_KEY_LEN);
    CryptoPP::Kalyna512::Encryption kl_enc(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN], KL_KEY_LEN);
    CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN + KL_IV_LEN], HMAC_KEY_LEN);
    hmac.Update(in_header, HEADER_LEN);
    hmac.Update(salt, SALT_LEN);
    
    CryptoPP::SecByteBlock chunk(CHUNK_LEN);
    size_t chunk_len = 0;
    unsigned char read_hash[HMAC_HASH_LEN];
    CryptoPP::SecByteBlock t3f_iv(T3F_IV_LEN);
    CryptoPP::SecByteBlock kl_iv(KL_IV_LEN);
    memcpy(t3f_iv.data(), &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN], T3F_IV_LEN);
    memcpy(kl_iv.data(), &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN], KL_IV_LEN);
    while ((chunk_len = fread(chunk, 1, CHUNK_LEN, input)) > 0) {
        check_fatal_err(chunk_len != CHUNK_LEN && ferror(input), "cannot read input.");
        if (chunk_len < CHUNK_LEN && chunk_len > HMAC_HASH_LEN) {
            chunk_len -= HMAC_HASH_LEN;
            memcpy(read_hash, &chunk[chunk_len], HMAC_HASH_LEN);
        } else if (chunk_len == HMAC_HASH_LEN) {
            memcpy(read_hash, chunk, HMAC_HASH_LEN);
            break;
        }
        hmac.Update(chunk, chunk_len);
        kl_decrypt_chunk(kl_enc, kl_dec, chunk, chunk_len, kl_iv);
        t3f_decrypt_chunk(t3f_enc, t3f_dec, chunk, chunk_len, t3f_iv);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len, "cannot write to file.");
    }
    unsigned char hash[HMAC_HASH_LEN];
    hmac.Final(hash);
    check_fatal_err(memcmp(hash, read_hash, HMAC_HASH_LEN) != 0, "wrong HMAC.");
                    
    std::cout << "decrypt " << timer.ElapsedTimeAsDouble() << std::endl;
}

void t3f_decrypt(CryptoPP::Threefish1024::Decryption &t3f, unsigned char *chunk, size_t chunk_len, unsigned char *t3f_iv) {
    uint32_t i = 0;
    unsigned char tmp[T3F_BLOCK_LEN];
    for (; chunk_len >= T3F_BLOCK_LEN; ++i, chunk_len -= T3F_BLOCK_LEN) {
        memcpy(tmp, &chunk[i * T3F_BLOCK_LEN], T3F_BLOCK_LEN);
        t3f.ProcessBlock(&chunk[i * T3F_BLOCK_LEN], &chunk[i * T3F_BLOCK_LEN]);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            chunk[i * T3F_BLOCK_LEN + j] = t3f_iv[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        memcpy(t3f_iv, tmp, T3F_BLOCK_LEN);
    }
    check_fatal_err(chunk_len != 0, "plaintext must be a multiple of the block size (128 bytes).");
}
void t3f_decrypt_chunk(CryptoPP::Threefish1024::Encryption &t3f_enc, CryptoPP::Threefish1024::Decryption &t3f_dec, unsigned char *chunk, size_t chunk_len, unsigned char *t3f_iv) {
    size_t tail = chunk_len % T3F_BLOCK_LEN;
    if (tail == 0) {
        t3f_decrypt(t3f_dec, chunk, chunk_len, t3f_iv);
    } else {
        if (chunk_len <= T3F_BLOCK_LEN) {
            t3f_enc.ProcessBlock(t3f_iv, t3f_iv);
            for (uint32_t j = 0; j < chunk_len; ++j) {
                chunk[j] = t3f_iv[j] ^ chunk[j];
            }
        } else {
            unsigned char tmp[T3F_BLOCK_LEN];
            t3f_dec.ProcessBlock(&chunk[chunk_len - T3F_BLOCK_LEN - tail], tmp);
            memcpy(&chunk[chunk_len], &tmp[tail], T3F_BLOCK_LEN - tail);
            memcpy(tmp, &chunk[chunk_len - tail], T3F_BLOCK_LEN);
            memcpy(&chunk[chunk_len - tail], &chunk[chunk_len - T3F_BLOCK_LEN - tail], T3F_BLOCK_LEN);
            memcpy(&chunk[chunk_len - T3F_BLOCK_LEN - tail], tmp, T3F_BLOCK_LEN);
            size_t new_chunk_len = chunk_len + T3F_BLOCK_LEN - tail;
            t3f_decrypt(t3f_dec, chunk, new_chunk_len, t3f_iv);
        }
    }
}
void kl_decrypt(CryptoPP::Kalyna512::Decryption &kl, unsigned char *chunk, size_t chunk_len, unsigned char *kl_iv) {
    uint32_t i = 0;
    unsigned char tmp[KL_BLOCK_LEN];
    for (; chunk_len >= KL_BLOCK_LEN; ++i, chunk_len -= KL_BLOCK_LEN) {
        memcpy(tmp, &chunk[i * KL_BLOCK_LEN], KL_BLOCK_LEN);
        kl.ProcessBlock(&chunk[i * KL_BLOCK_LEN], &chunk[i * KL_BLOCK_LEN]);
        for (uint32_t j = 0; j < KL_BLOCK_LEN; ++j) {
            chunk[i * KL_BLOCK_LEN + j] = kl_iv[j] ^ chunk[i * KL_BLOCK_LEN + j];
        }
        memcpy(kl_iv, tmp, KL_BLOCK_LEN);
    }
    check_fatal_err(chunk_len != 0, "plaintext must be a multiple of the block size (64 bytes).");
}
void kl_decrypt_chunk(CryptoPP::Kalyna512::Encryption &kl_enc, CryptoPP::Kalyna512::Decryption &kl_dec, unsigned char *chunk, size_t chunk_len, unsigned char *kl_iv) {
    size_t tail = chunk_len % KL_BLOCK_LEN;
    if (tail == 0) {
        kl_decrypt(kl_dec, chunk, chunk_len, kl_iv);
    } else {
        if (chunk_len <= KL_BLOCK_LEN) {
            kl_enc.ProcessBlock(kl_iv, kl_iv);
            for (uint32_t j = 0; j < chunk_len; ++j) {
                chunk[j] = kl_iv[j] ^ chunk[j];
            }
        } else {
            unsigned char tmp[KL_BLOCK_LEN];
            kl_dec.ProcessBlock(&chunk[chunk_len - KL_BLOCK_LEN - tail], tmp);
            memcpy(&chunk[chunk_len], &tmp[tail], KL_BLOCK_LEN - tail);
            memcpy(tmp, &chunk[chunk_len - tail], KL_BLOCK_LEN);
            memcpy(&chunk[chunk_len - tail], &chunk[chunk_len - KL_BLOCK_LEN - tail], KL_BLOCK_LEN);
            memcpy(&chunk[chunk_len - KL_BLOCK_LEN - tail], tmp, KL_BLOCK_LEN);
            size_t new_chunk_len = chunk_len + KL_BLOCK_LEN - tail;
            kl_decrypt(kl_dec, chunk, new_chunk_len, kl_iv);
        }
    }
}

void make_key(unsigned char *master_key, unsigned char *enc_key, unsigned char *salt) {
    CryptoPP::Timer timer;
    timer.StartTimer();
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt, SALT_LEN, enc_key, ENC_KEY_LEN) != ARGON2_OK, "Argon2 failed.");
    std::cout << "argon2  " << timer.ElapsedTimeAsDouble() << std::endl;
}