
#include "hash.h"

namespace crypto {

    const char *getHashTypeString(hash_types hash) {
        switch(hash) {
            case md4:
                return "md4";
            case md5:
                return "md5";
            case md5_sha1:
                return "md5-sha1";
            case blake2b512:
                return "blake2b512";
            case blake2s256:
                return "blake2s256";
            case sha1:
                return "sha1";
            case sha224:
                return "sha224";
            case sha256:
                return "sha256";
            case sha384:
                return "sha384";
            case sha512:
                return "sha512";
            case sha512_224:
                return "sha512-224";
            case sha512_256:
                return "sha512-256";
            case sha3_224:
                return "sha3-224";
            case sha3_256:
                return "sha3-256";
            case sha3_384:
                return "sha3-384";
            case sha3_512:
                return "sha3-512";
            case shake128:
                return "shake128";
            case shake256:
                return "shake256";
            case mdc2:
                return "mdc2";
            case ripemd160:
                return "ripemd160";
            case whirlpool:
                return "whirlpool";
            case sm3:
                return "sm3";
        }
        return NULL;
    }
    
}
