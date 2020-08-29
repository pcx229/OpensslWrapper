
#ifndef _CRYPTO_EC_H_
#define _CRYPTO_EC_H_

#include <iostream>
using namespace std;

#include <exception>

#include <cstdio>
#include <cstring>

#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#include "hash.h"
using namespace crypto;

#include "openssl_exception.h"


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
        AUTO, // detect format based on file extension or set to default DER
        PEM, 
        DER 
    };

    /**
     * determine what is the format to use when an AUTO format is given.
     * if the key file name extension has explicit specific format(like .pem or .der)
     * that format will be selected, otherwise DER is selected by default.
     * @param file_path_key a file path for the key file
     * @return PEM or DER format
     */
    file_eckey_format getECKEYFormatOfAuto(const char *file_path_key);

    enum cipher {
        no_cipher,
        des_cfb,
        des_cfb1,
        des_cfb8,
        des_ede_cfb,
        des_ede3_cfb1,
        des_ede3_cfb8,
        des_ofb,
        des_ede_ofb,
        des_ede3_ofb,
        des_cbc,
        des_ede_cbc,
        des_ede3_cbc,
        desx_cbc,
        idea_cfb,
        idea_ofb,
        idea_cbc,
        rc2_cbc,
        rc2_40_cbc,
        rc2_64_cbc,
        rc2_cfb,
        rc2_ofb,
        bf_cbc,
        bf_cfb,
        bf_ofb,
        cast5_cbc,
        cast5_cfb,
        cast5_ofb,
        aes_128_cbc,
        aes_128_cfb1,
        aes_128_cfb8,
        aes_128_cfb,
        aes_128_ofb,
        aes_128_ctr,
        aes_128_ccm,
        aes_128_gcm,
        aes_128_xts,
        aes_128_ocb,
        aes_192_cbc,
        aes_192_cfb1,
        aes_192_cfb8,
        aes_192_cfb,
        aes_192_ofb,
        aes_192_ctr,
        aes_192_ccm,
        aes_192_gcm,
        aes_192_ocb,
        aes_256_cbc,
        aes_256_cfb1,
        aes_256_cfb8,
        aes_256_cfb,
        aes_256_ofb,
        aes_256_ctr,
        aes_256_ccm,
        aes_256_gcm,
        aes_256_xts,
        aes_256_ocb,
        aes_128_cbc_hmac_sha1,
        aes_256_cbc_hmac_sha1,
        aes_128_cbc_hmac_sha256,
        aes_256_cbc_hmac_sha256,
        aria_128_cbc,
        aria_128_cfb1,
        aria_128_cfb8,
        aria_128_cfb,
        aria_128_ctr,
        aria_128_ofb,
        aria_128_gcm,
        aria_128_ccm,
        aria_192_cbc,
        aria_192_cfb1,
        aria_192_cfb8,
        aria_192_cfb,
        aria_192_ctr,
        aria_192_ofb,
        aria_192_gcm,
        aria_192_ccm,
        aria_256_cbc,
        aria_256_cfb1,
        aria_256_cfb8,
        aria_256_cfb,
        aria_256_ctr,
        aria_256_ofb,
        aria_256_gcm,
        aria_256_ccm,
        camellia_128_cbc,
        camellia_128_cfb1,
        camellia_128_cfb8,
        camellia_128_cfb,
        camellia_128_ofb,
        camellia_128_ctr,
        camellia_192_cbc,
        camellia_192_cfb1,
        camellia_192_cfb8,
        camellia_192_cfb,
        camellia_192_ofb,
        camellia_192_ctr,
        camellia_256_cbc,
        camellia_256_cfb1,
        camellia_256_cfb8,
        camellia_256_cfb,
        camellia_256_ofb,
        camellia_256_ctr,
        chacha20,
        chacha20_poly1305,
        seed_cbc,
        seed_cfb,
        seed_ofb,
        sm4_cbc,
        sm4_cfb,
        sm4_ofb,
        sm4_ctr
    };

    const char *cipherToString(cipher c);

    /**
     *  elliptic curve class can generate keys + sign and verify a certificate
     */
    class EC {

        EVP_MD_CTX *mdctx = NULL;
        BN_CTX *bnctx = NULL;

        EC_KEY *eckey_private = NULL, *eckey_public = NULL;
        EVP_PKEY *evkey_private = NULL, *evkey_public = NULL;

        /**
         * create a data container for functions used in this context
         * @throw OpensslException
         */
        void buildContext();

        public:

        /**
         * load private and public keys, AUTO detect file format.
         * @param file_private_key_path private key file path
         * @param file_public_key_path public key file path
         * @throw invalid_argument, OpensslException, runtime_error
         */
        EC(const char *file_private_key_path=NULL, const char *file_public_key_path=NULL);

        /**
         * load private and public keys.
         * @param file_private_key_path private key file path
         * @param private_key_format private key file format
         * @param file_public_key_path public key file path
         * @param public_key_format public key file format
         * @throw invalid_argument, OpensslException, runtime_error
         */
        EC(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path=NULL, file_eckey_format public_key_format=AUTO);

        ~EC();

        /**
         * remove private/public keys
         */
        void clear();

        /**
         * load private and public keys, AUTO detect file format.
         * @param file_private_key_path private key file path
         * @param file_public_key_path public key file path
         * @throw invalid_argument, OpensslException, runtime_error
         */
        void load(const char *file_private_key_path, const char *file_public_key_path);

        /**
         * load private and public keys.
         * @param file_private_key_path private key file path
         * @param private_key_format private key file format
         * @param file_public_key_path public key file path
         * @param public_key_format public key file format
         * @throw invalid_argument, OpensslException, runtime_error
         */
        void load(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format);

        /**
         * load private key, clear any previous key pair.
         * @param file_private_key_path private key file path
         * @param private_key_format private key file format
         * @password required only if the file is encrypted
         * @throw invalid_argument, OpensslException, runtime_error
         */
        void load_private(const char *file_private_key_path, file_eckey_format private_key_format=AUTO, const char *password=NULL);

        /**
         * load public key, any previous public key is discarded.
         * note: public key is not tested if it match the private part.
         * @param file_public_key_path public key file path
         * @param public_key_format public key file format
         * @throw invalid_argument, OpensslException, runtime_error
         */
        void load_public(const char *file_public_key_path, file_eckey_format public_key_format=AUTO);

        /**
         * load private and public keys.
         * the format is SubjectPublicKeyInfo
         * @param private_key private key as base64 encoded string
         * @param public_key public key as base64 encoded string
         * @throw OpensslException, runtime_error
         */
        void load(const string &private_key, const string &public_key);

        /**
         * load private key.
         * the format is SubjectPublicKeyInfo
         * @param private_key private key string
         * @param data_encoding private key string encoding
         * @throw OpensslException, runtime_error
         */
        void load_private(const string &private_key, data_encoding format=BASE64);

        /**
         * load public key.
         * the format is SubjectPublicKeyInfo
         * @param public_key public key string
         * @param data_encoding public key string encoding
         * @throw OpensslException, runtime_error
         */
        void load_public(const string &public_key, data_encoding format=BASE64);

        /**
         * save private and public keys to files.
         * @param file_private_key_path file where private key will be saved to
         * @param file_public_key_path file where public key will be saved to
         * @throw invalid_argument, OpensslException, runtime_error
		 */
        void save(const char *file_private_key_path, const char *file_public_key_path) const;

        /**
         * save private and public keys to files.
         * @param file_private_key_path file where private key will be saved to
         * @param private_key_format private key output file format
         * @param file_public_key_path file where public key will be saved to
         * @param public_key_format public key output file format
         * @throw invalid_argument, OpensslException, runtime_error
		 */
        void save(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format) const;

        /**
         * write private key to a file.
         * @param file_private_key_path file where private key will be saved to
         * @param private_key_format private key output file format, if not specified then do AUTO determination for desired format.
         * @param cipher_type optional if encrypted key file is wanted.
         * 		  			  dose not support DER file output format.
         * @param password paired with cipher_type parameter to use for encryption pass phase.
         * @throw invalid_argument, OpensslException, runtime_error
         */
        void save_private(const char *file_private_key_path, file_eckey_format private_key_format=AUTO, cipher cipher_type=no_cipher, const char *password=NULL) const;

        /**
         * write public key to a file.
         * @param file_public_key_path file where public key will be saved to
         * @param public_key_format public key output file format, if not specified then do AUTO determination for desired format.
		 * @throw invalid_argument, OpensslException, runtime_error
		 */
        void save_public(const char *file_public_key_path, file_eckey_format public_key_format=AUTO) const;

        /**
         * get private key as a string.
         * the format is SubjectPublicKeyInfo
         * @param format choose different encoding for key output
         * @return the private key as a string
         * @throw runtime_error, OpensslException
		 */
        const string get_private(data_encoding format=BASE64) const;

        /**
         * get public key as a string.
         * the format is SubjectPublicKeyInfo
         * @param format choose different encoding for key output
         * @return the public key as a string
         * @throw runtime_error, OpensslException
         */
        const string get_public(data_encoding format=BASE64) const;

        enum public_key_point_format{ COMPRESSED, UNCOMPRESSED, HYBRID };
        enum public_key_point_encoding{ HEX, BINARY };

        /**
         * get a point representation of the public key compressed or not.
         * @param form in what form the point should be presented COMPRESSED, UNCOMPRESSED or HYBRID
         * @param output encoding for the output string HEX or BINARY
         * @return a string with the point
         */
        const string get_public_point(public_key_point_format form, public_key_point_encoding output=HEX) const;

        /**
         * set public key by a point.
         * @param pkey the public key point string
         * @param curve type of elliptic curve this key uses
         * @param input encoding for the input string HEX or BINARY
         */
        void set_public_by_point(const string &pkey, elliptic_curve curve, public_key_point_encoding input=HEX);

        /**
         * generate private and public keys.
         * @param curve the elliptic curve to use for key generation
         */
        void generate_keys(elliptic_curve curve);

        /**
         * generate public key with the private key.
         */
        void generate_public();

        /**
         * create a signature for a data using the private key.
         * @param hash a hash function is required, elliptic curves only support
         * 				sha1, sha224, sha256, sha384 and sha512 hashing.
         * @param data data to create signature for
         * @param signature output parameter for the result signature
         * @throw invalid_argument, OpensslException, runtime_error
         */
        void sign(hash_types hash, istream &data, ostream &signature) const;

        /**
         * verify data with a given signature using the public key.
         * @param hash a hash function that was used for signing
         * @param data data to verify with the signature
         * @param signature the signature
         * @return true if the signature was generated from the data
         * @throw invalid_argument, OpensslException, runtime_error
         */
        bool verify(hash_types hash, istream &data, istream &signature) const;

    };

}

#endif
