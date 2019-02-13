#include <iostream>

#include <cryptopp/hrtimer.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>

#define STB_LIB_IMPLEMENTATION
#include "stb/stb_lib.h"

#include "argon2/argon2.h"

const unsigned int T3F_TWEAK_LEN = 16;
const unsigned int T3F_KEY_LEN = 128;
const unsigned int T3F_BLOCK_LEN = 128;
const unsigned int T3F_IV_LEN = 128;
const unsigned int NUM_BLOCKS = 2048;
const size_t CHUNK_LEN = NUM_BLOCKS * T3F_BLOCK_LEN;

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

const uint32_t T = 9;
const uint32_t M = 1 << 19;
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
    check_fatal_err(stb_filelen(f) != MASTER_KEY_LEN, "keyfile must have exactly 256 bytes.");
    check_fatal_err(fread(master_key, 1, MASTER_KEY_LEN, f) != MASTER_KEY_LEN, "cannot read key from file.");
    fclose(f);
}

void encrypt(FILE *input, FILE *output, unsigned char *master_key);
void decrypt(FILE *input, FILE *output, unsigned char *master_key);
void make_key(unsigned char *master_key, unsigned char *enc_key, unsigned char *salt);

int main(int argc, char **argv) {

    CryptoPP::SecByteBlock master_key(MASTER_KEY_LEN);
    try {
        if (argc == 3 && strcmp(argv[1], "-kf") == 0) {
            CryptoPP::OS_GenerateRandomBlock(false, master_key, MASTER_KEY_LEN);
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
                    std::cout << "File exists. Do you want to overwrite? (y/n) " << std::flush;
                    std::cin >> yn;
                } while (yn != "n" && yn != "N" && yn != "y" && yn != "Y");
                if (yn == "n" || yn == "N") {
                    std::cout << "Please choose a different output file." << std::endl;
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
    CryptoPP::OS_GenerateRandomBlock(false, salt, SALT_LEN);
    check_fatal_err(fwrite(salt, 1, SALT_LEN, output) != SALT_LEN, "cannot write salt.");
    unsigned char hash[HMAC_HASH_LEN];
    check_fatal_err(fwrite(hash, 1, HMAC_HASH_LEN, output) != HMAC_HASH_LEN, "cannot write hash.");

    CryptoPP::SecByteBlock enc_key(ENC_KEY_LEN);
    make_key(master_key, enc_key, salt);
    CryptoPP::SecureWipeBuffer(master_key, MASTER_KEY_LEN);

    CryptoPP::Timer timer;
    timer.StartTimer();
    
    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN], T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters t3f_params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(t3f_params);
    CryptoPP::CTR_Mode_ExternalCipher::Encryption t3f_ctr(t3f, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN]);
    CryptoPP::CTR_Mode<CryptoPP::Kalyna512>::Encryption kl_ctr(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN], KL_KEY_LEN, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN]);
    CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN + KL_IV_LEN], HMAC_KEY_LEN);
    CryptoPP::SecureWipeBuffer(enc_key.data(), ENC_KEY_LEN);
    
    hmac.Update(header, HEADER_LEN);
    hmac.Update(salt, SALT_LEN);
    CryptoPP::SecByteBlock chunk(CHUNK_LEN);
    size_t chunk_len = 0;
    while ((chunk_len = fread(chunk, 1, CHUNK_LEN, input)) > 0) {
        check_fatal_err(chunk_len != CHUNK_LEN && ferror(input), "cannot read input.");
        t3f_ctr.ProcessData(chunk, chunk, chunk_len);
        kl_ctr.ProcessData(chunk, chunk, chunk_len);
        hmac.Update(chunk, chunk_len);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len, "cannot write to file.");
    }
    hmac.Final(hash);
    fseek(output, HEADER_LEN + SALT_LEN, SEEK_SET);
    check_fatal_err(fwrite(hash, 1, HMAC_HASH_LEN, output) != HMAC_HASH_LEN, "cannot write HMAC.");
    
    std::cout << "encrypt " << timer.ElapsedTimeAsDouble() << std::endl;
}

void decrypt(FILE *input, FILE *output, unsigned char *master_key) {
    
    unsigned char in_header[HEADER_LEN];
    check_fatal_err(fread(in_header, 1, HEADER_LEN, input) != HEADER_LEN, "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0, "wrong header.");
    unsigned char salt[SALT_LEN];
    check_fatal_err(fread(salt, 1, SALT_LEN, input) != SALT_LEN, "cannot read salt.");
    unsigned char read_hash[HMAC_HASH_LEN];
    check_fatal_err(fread(read_hash, 1, HMAC_HASH_LEN, input) != HMAC_HASH_LEN, "cannot read hash.");
                    
    CryptoPP::SecByteBlock enc_key(ENC_KEY_LEN);
    make_key(master_key, enc_key, salt);
    CryptoPP::SecureWipeBuffer(master_key, MASTER_KEY_LEN);
    
    CryptoPP::Timer timer;
    timer.StartTimer();
    
    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN], T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters t3f_params = CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(t3f_params);
    CryptoPP::CTR_Mode_ExternalCipher::Encryption t3f_ctr(t3f, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN]);
    CryptoPP::CTR_Mode<CryptoPP::Kalyna512>::Encryption kl_ctr(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN], KL_KEY_LEN, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN]);
    CryptoPP::HMAC<CryptoPP::SHA3_512> hmac(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_IV_LEN + KL_KEY_LEN + KL_IV_LEN], HMAC_KEY_LEN);
    CryptoPP::SecureWipeBuffer(enc_key.data(), ENC_KEY_LEN);
    
    hmac.Update(in_header, HEADER_LEN);
    hmac.Update(salt, SALT_LEN);
    CryptoPP::SecByteBlock chunk(CHUNK_LEN);
    size_t chunk_len = 0;
    while ((chunk_len = fread(chunk, 1, CHUNK_LEN, input)) > 0) {
        check_fatal_err(chunk_len != CHUNK_LEN && ferror(input), "cannot read input.");
        hmac.Update(chunk, chunk_len);
        kl_ctr.ProcessData(chunk, chunk, chunk_len);
        t3f_ctr.ProcessData(chunk, chunk, chunk_len);
        check_fatal_err(fwrite(chunk, 1, chunk_len, output) != chunk_len, "cannot write to file.");
    }
    unsigned char hash[HMAC_HASH_LEN];
    hmac.Final(hash);
    check_fatal_err(memcmp(hash, read_hash, HMAC_HASH_LEN) != 0, "wrong HMAC.");
                    
    std::cout << "decrypt " << timer.ElapsedTimeAsDouble() << std::endl;
}

void make_key(unsigned char *master_key, unsigned char *enc_key, unsigned char *salt) {
    CryptoPP::Timer timer;
    timer.StartTimer();
    argon2_context ag2_ctx = {
        enc_key,           /* output array */
        ENC_KEY_LEN,       /* output length */
        master_key,        /* password array */
        MASTER_KEY_LEN,    /* password length */
        salt,              /* salt array */
        SALT_LEN,          /* salt length */
        NULL, 0,           /* optional secret data */
        NULL, 0,           /* optional associated data */
        T, M, P, P,
        ARGON2_VERSION_13, /* algorithm version */
        NULL, NULL,        /* custom memory allocation / deallocation functions */
        ARGON2_DEFAULT_FLAGS
    };
    check_fatal_err(argon2id_ctx(&ag2_ctx) != ARGON2_OK, "Argon2 failed.");
    std::cout << "argon2  " << timer.ElapsedTimeAsDouble() << std::endl;
}