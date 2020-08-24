
#ifndef _CRYPTO_EC_H_
#define _CRYPTO_EC_H_

#include <iostream>
using namespace std;

#include <exception>

#include <cstdio>
#include <cstring>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include "hash.h"
using namespace crypto;

namespace crypto {
    
    /*
     *  eliptic curve key generation, sign and verify, can handle same functionality as the following commands:
     *      - create pivate key
     *      openssl ecparam -name %elliptic_curve -genkey -noout -outform PEM/DER -out %file_private_key
     *      openssl ec -in %file_private_key %cipher_type -passout pass:%password -out %file_private_key
     *      - create public key
     *      openssl ec -inform PEM/DER -in %file_privare_key -pubout -outform DER/PEM -out %file_public_key
     *      - signature of a file with private key
     *      openssl dgst -sha1/-sha224/-sha256/-sha384/-sha512 -sign %file_private_key -out %file_signature %file_data
     *      - verify a signature with public key
     *      openssl dgst -sha1/-sha224/-sha256/-sha384/-sha512 -verify %file_public_key -signature %file_signature %file_data
     */
    
    enum elliptic_curve{ 
        secp256k1, 
        P_256, 
        P_224, 
        P_384, 
        P_521, 
        X25519 
    };

    int getEllipticCurveNID(elliptic_curve curve);

    enum file_eckey_format{ 
        AUTO, 
        PEM, 
        DER 
    };

    file_eckey_format getECKEYFormatOfAuto(const char *file_path_key);

    enum cipher {
        no_cipher,
        des_ecb,
        des_ede,
        des_ede3,
        des_ede_ecb,
        des_ede3_ecb,
        des_cfb64,
        des_cfb1,
        des_cfb8,
        des_ede_cfb64,
        des_ede3_cfb64,
        des_ede3_cfb1,
        des_ede3_cfb8,
        des_ofb,
        des_ede_ofb,
        des_ede3_ofb,
        des_cbc,
        des_ede_cbc,
        des_ede3_cbc,
        desx_cbc,
        des_ede3_wrap,
        rc4,
        rc4_40,
        rc4_hmac_md5,
        idea_ecb,
        idea_cfb64,
        idea_ofb,
        idea_cbc,
        rc2_ecb,
        rc2_cbc,
        rc2_40_cbc,
        rc2_64_cbc,
        rc2_cfb64,
        rc2_ofb,
        bf_ecb,
        bf_cbc,
        bf_cfb64,
        bf_ofb,
        cast5_ecb,
        cast5_cbc,
        cast5_cfb64,
        cast5_ofb,
        rc5_32_12_16_cbc,
        rc5_32_12_16_ecb,
        rc5_32_12_16_cfb64,
        rc5_32_12_16_ofb,
        aes_128_ecb,
        aes_128_cbc,
        aes_128_cfb1,
        aes_128_cfb8,
        aes_128_cfb128,
        aes_128_ofb,
        aes_128_ctr,
        aes_128_ccm,
        aes_128_gcm,
        aes_128_xts,
        aes_128_wrap,
        aes_128_wrap_pad,
        aes_128_ocb,
        aes_192_ecb,
        aes_192_cbc,
        aes_192_cfb1,
        aes_192_cfb8,
        aes_192_cfb128,
        aes_192_ofb,
        aes_192_ctr,
        aes_192_ccm,
        aes_192_gcm,
        aes_192_wrap,
        aes_192_wrap_pad,
        aes_192_ocb,
        aes_256_ecb,
        aes_256_cbc,
        aes_256_cfb1,
        aes_256_cfb8,
        aes_256_cfb128,
        aes_256_ofb,
        aes_256_ctr,
        aes_256_ccm,
        aes_256_gcm,
        aes_256_xts,
        aes_256_wrap,
        aes_256_wrap_pad,
        aes_256_ocb,
        aes_128_cbc_hmac_sha1,
        aes_256_cbc_hmac_sha1,
        aes_128_cbc_hmac_sha256,
        aes_256_cbc_hmac_sha256,
        aes_128_siv,
        aes_192_siv,
        aes_256_siv,
        aria_128_ecb,
        aria_128_cbc,
        aria_128_cfb1,
        aria_128_cfb8,
        aria_128_cfb128,
        aria_128_ctr,
        aria_128_ofb,
        aria_128_gcm,
        aria_128_ccm,
        aria_192_ecb,
        aria_192_cbc,
        aria_192_cfb1,
        aria_192_cfb8,
        aria_192_cfb128,
        aria_192_ctr,
        aria_192_ofb,
        aria_192_gcm,
        aria_192_ccm,
        aria_256_ecb,
        aria_256_cbc,
        aria_256_cfb1,
        aria_256_cfb8,
        aria_256_cfb128,
        aria_256_ctr,
        aria_256_ofb,
        aria_256_gcm,
        aria_256_ccm,
        camellia_128_ecb,
        camellia_128_cbc,
        camellia_128_cfb1,
        camellia_128_cfb8,
        camellia_128_cfb128,
        camellia_128_ofb,
        camellia_128_ctr,
        camellia_192_ecb,
        camellia_192_cbc,
        camellia_192_cfb1,
        camellia_192_cfb8,
        camellia_192_cfb128,
        camellia_192_ofb,
        camellia_192_ctr,
        camellia_256_ecb,
        camellia_256_cbc,
        camellia_256_cfb1,
        camellia_256_cfb8,
        camellia_256_cfb128,
        camellia_256_ofb,
        camellia_256_ctr,
        chacha20,
        chacha20_poly1305,
        seed_ecb,
        seed_cbc,
        seed_cfb128,
        seed_ofb,
        sm4_ecb,
        sm4_cbc,
        sm4_cfb128,
        sm4_ofb,
        sm4_ctr
    };

    const char *cipherToString(cipher c);

    /* elliptic curve class can generate keys + sign and verify a certificate */ 
    class EC {

        EC_KEY *eckey_private = NULL, *eckey_public = NULL;
        EVP_PKEY *evkey_private = NULL, *evkey_public = NULL;

        public:

        EC();
        EC(const char *file_private_key_path, const char *file_public_key_path);
        EC(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format);

        ~EC();

        void clear();

        void load(const char *file_private_key_path, const char *file_public_key_path);
        void load(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format);
        void load_private(const char *file_private_key_path, file_eckey_format private_key_format=AUTO, const char *password=NULL);
        void load_public(const char *file_public_key_path, file_eckey_format public_key_format=AUTO);
        void load(const string &private_key, const string &public_key);
        void load_private(const string &private_key, data_encoding format=BASE64);
        void load_public(const string &public_key, data_encoding format=BASE64);

        void save(const char *file_private_key_path, const char *file_public_key_path);
        void save(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format);
        void save_private(const char *file_private_key_path, file_eckey_format private_key_format=AUTO, cipher cipher_type=no_cipher, const char *password=NULL);
        void save_public(const char *file_public_key_path, file_eckey_format public_key_format=AUTO);
        const string get_private(data_encoding format=BASE64);
        const string get_public(data_encoding format=BASE64);

        void generate_keys(elliptic_curve curve);

        void sign(hash_types hash, istream &data, ostream &signature);

        bool verify(hash_types hash, istream &data, istream &signature);

    };

}

#endif