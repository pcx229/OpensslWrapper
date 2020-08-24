
#ifndef _CRYPTO_HASH_H_
#define _CRYPTO_HASH_H_

#include <iostream>
using namespace std;

#include <sstream>
#include <string>
#include <iomanip>
#include <exception>

#include <cstring>

#include <openssl/evp.h>

#include "encoding.h"
#include "OpensslException.h"

namespace crypto {

    /** 
     *  this library should handle about the same functionality as the following command:
     *      openssl dgst -%hash -hex/-binary < %stream/%string
     */
    
    enum hash_types
    {
        md4,
        md5,
        md5_sha1,
        blake2b512,
        blake2s256,
        sha1,
        sha224,
        sha256,
        sha384,
        sha512,
        sha512_224,
        sha512_256,
        sha3_224,
        sha3_256,
        sha3_384,
        sha3_512,
        shake128,
        shake256,
        mdc2,
        ripemd160,
        whirlpool,
        sm3
    };

    const char *getHashTypeString(hash_types hash);

    /**
     * the hash class is a wrapper over the hash functions in openssl EVP library,
     * with this class you can hash data with different algorithms.
     * hash class allow copying state of current hashing progress which
     * can be useful when hashing a big chunks of data that only differ
     * in last few bytes.
     * only support algorithms that EVP_get_digestbyname can receive.
     */
    template <hash_types type>
    class hash {

        EVP_MD_CTX *mdctx = NULL;

        unsigned char md_value[EVP_MAX_MD_SIZE];
        unsigned int md_len = EVP_MAX_MD_SIZE;

        bool is_over = false;

        void init();

        public:

        /**
         * an empty string hash
         */
        hash();

        /**
         * the hash will be initialized and then updated with the string given
         * @param data hash the bytes in this string
         */
        hash(const string &data);

        /**
         * the hash will be initialized and then updated with the stream given
         * @param data hash the bytes in this stream
         */
        hash(istream &data);

        /**
         * same as = operator
         * @param other a hash with the same algorithm as this one to clone
         */
        hash(const hash &other);

        ~hash();

        /**
         * copy the hash given to this one.
         * if the other hash state is over already this hash
         * will also be over and thus unable to update.
         * @param other hash to copy
         * @return this hash
         */
        hash &operator=(const hash &other);

        /**
         * continue hashing with bytes from the string given, this function can
         * be called multiple times.
         * @param data string to put in the hash
         * @return this hash
         */
        hash &update(const string &data);

        /**
         * same as update() only with an operator
         * @param data string to put in the hash
         * @return this hash
         */
        hash &operator<<(const string &data);

        /**
         * continue hashing with bytes from the stream given, this function can
         * be called multiple times.
         * @param data stream to put in the hash
         * @return this hash
         */
        hash &update(istream &data);

        /**
         * same as update() only with an operator
         * @param data stream to put in the hash
         * @return this hash
         */
        hash &operator<<(istream &data);

        /**
         * make the digest value from the hash and return it.
         * ending the hashing progress, after this function is called no
         * more updates can be made.
         * calling to this function after hashing is over will return the
         * result digest value.
         * @param enc output encoding of the digest value, HEX is default
         * @return result digest value
         */
        string digest(data_encoding enc=HEX);

        /**
         * ending the hashing progress, see call to digest()
         * @return the result digest value of this hash
         */
        operator string() const;
    };
}

#include "hash_tmps.h"

#endif
