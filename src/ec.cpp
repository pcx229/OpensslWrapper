
#include "ec.h"

namespace crypto {

    int getEllipticCurveNID(elliptic_curve curve) {
        switch(curve) {
            case secp256k1:
                return NID_secp256k1;
            case P_256:
                return NID_X9_62_prime256v1;
            case P_224:
                return NID_secp224r1;
            case P_384:
                return NID_secp384r1;
            case P_521:
                return NID_secp521r1;
            case X25519:
                return NID_X25519;
        }
        return -1;
    }

    /**
     * check if a string ends with some string.
     * example: ends_with("hello world", "world") = true
     * @param value any string
     * @param ending a string to check if its in the ending of value
     * @return true if the value string ends with the ending string
     */
    inline bool ends_with(std::string const &value, std::string const &ending)
    {
        if (ending.size() > value.size()) return false;
        return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
    }

    file_eckey_format getECKEYFormatOfAuto(const char *file_path_key) {
        if(ends_with(file_path_key, ".pem")) {
            return PEM;
        }
        return DER;
    }

    const char *cipherToString(cipher c) {
        switch(c) {
            case des_ecb:
                return "des-ecb";
            case des_ede:
                return "des-ede";
            case des_ede3:
                return "des-ede3";
            case des_ede_ecb:
                return "des-ede-ecb";
            case des_ede3_ecb:
                return "des-ede3-ecb";
            case des_cfb64:
                return "des-cfb64";
            case des_cfb1:
                return "des-cfb1";
            case des_cfb8:
                return "des-cfb8";
            case des_ede_cfb64:
                return "des-ede-cfb64";
            case des_ede3_cfb64:
                return "des-ede3-cfb64";
            case des_ede3_cfb1:
                return "des-ede3-cfb1";
            case des_ede3_cfb8:
                return "des-ede3-cfb8";
            case des_ofb:
                return "des-ofb";
            case des_ede_ofb:
                return "des-ede-ofb";
            case des_ede3_ofb:
                return "des-ede3-ofb";
            case des_cbc:
                return "des-cbc";
            case des_ede_cbc:
                return "des-ede-cbc";
            case des_ede3_cbc:
                return "des-ede3-cbc";
            case desx_cbc:
                return "desx-cbc";
            case des_ede3_wrap:
                return "des-ede3-wrap";
            case rc4:
                return "rc4";
            case rc4_40:
                return "rc4-40";
            case rc4_hmac_md5:
                return "rc4-hmac-md5";
            case idea_ecb:
                return "idea-ecb";
            case idea_cfb64:
                return "idea-cfb64";
            case idea_ofb:
                return "idea-ofb";
            case idea_cbc:
                return "idea-cbc";
            case rc2_ecb:
                return "rc2-ecb";
            case rc2_cbc:
                return "rc2-cbc";
            case rc2_40_cbc:
                return "rc2-40-cbc";
            case rc2_64_cbc:
                return "rc2-64-cbc";
            case rc2_cfb64:
                return "rc2-cfb64";
            case rc2_ofb:
                return "rc2-ofb";
            case bf_ecb:
                return "bf-ecb";
            case bf_cbc:
                return "bf-cbc";
            case bf_cfb64:
                return "bf-cfb64";
            case bf_ofb:
                return "bf-ofb";
            case cast5_ecb:
                return "cast5-ecb";
            case cast5_cbc:
                return "cast5-cbc";
            case cast5_cfb64:
                return "cast5-cfb64";
            case cast5_ofb:
                return "cast5-ofb";
            case rc5_32_12_16_cbc:
                return "rc5-32-12-16-cbc";
            case rc5_32_12_16_ecb:
                return "rc5-32-12-16-ecb";
            case rc5_32_12_16_cfb64:
                return "rc5-32-12-16-cfb64";
            case rc5_32_12_16_ofb:
                return "rc5-32-12-16-ofb";
            case aes_128_ecb:
                return "aes-128-ecb";
            case aes_128_cbc:
                return "aes-128-cbc";
            case aes_128_cfb1:
                return "aes-128-cfb1";
            case aes_128_cfb8:
                return "aes-128-cfb8";
            case aes_128_cfb128:
                return "aes-128-cfb128";
            case aes_128_ofb:
                return "aes-128-ofb";
            case aes_128_ctr:
                return "aes-128-ctr";
            case aes_128_ccm:
                return "aes-128-ccm";
            case aes_128_gcm:
                return "aes-128-gcm";
            case aes_128_xts:
                return "aes-128-xts";
            case aes_128_wrap:
                return "aes-128-wrap";
            case aes_128_wrap_pad:
                return "aes-128-wrap-pad";
            case aes_128_ocb:
                return "aes-128-ocb";
            case aes_192_ecb:
                return "aes-192-ecb";
            case aes_192_cbc:
                return "aes-192-cbc";
            case aes_192_cfb1:
                return "aes-192-cfb1";
            case aes_192_cfb8:
                return "aes-192-cfb8";
            case aes_192_cfb128:
                return "aes-192-cfb128";
            case aes_192_ofb:
                return "aes-192-ofb";
            case aes_192_ctr:
                return "aes-192-ctr";
            case aes_192_ccm:
                return "aes-192-ccm";
            case aes_192_gcm:
                return "aes-192-gcm";
            case aes_192_wrap:
                return "aes-192-wrap";
            case aes_192_wrap_pad:
                return "aes-192-wrap-pad";
            case aes_192_ocb:
                return "aes-192-ocb";
            case aes_256_ecb:
                return "aes-256-ecb";
            case aes_256_cbc:
                return "aes-256-cbc";
            case aes_256_cfb1:
                return "aes-256-cfb1";
            case aes_256_cfb8:
                return "aes-256-cfb8";
            case aes_256_cfb128:
                return "aes-256-cfb128";
            case aes_256_ofb:
                return "aes-256-ofb";
            case aes_256_ctr:
                return "aes-256-ctr";
            case aes_256_ccm:
                return "aes-256-ccm";
            case aes_256_gcm:
                return "aes-256-gcm";
            case aes_256_xts:
                return "aes-256-xts";
            case aes_256_wrap:
                return "aes-256-wrap";
            case aes_256_wrap_pad:
                return "aes-256-wrap-pad";
            case aes_256_ocb:
                return "aes-256-ocb";
            case aes_128_cbc_hmac_sha1:
                return "aes-128-cbc-hmac-sha1";
            case aes_256_cbc_hmac_sha1:
                return "aes-256-cbc-hmac-sha1";
            case aes_128_cbc_hmac_sha256:
                return "aes-128-cbc-hmac-sha256";
            case aes_256_cbc_hmac_sha256:
                return "aes-256-cbc-hmac-sha256";
            case aes_128_siv:
                return "aes-128-siv";
            case aes_192_siv:
                return "aes-192-siv";
            case aes_256_siv:
                return "aes-256-siv";
            case aria_128_ecb:
                return "aria-128-ecb";
            case aria_128_cbc:
                return "aria-128-cbc";
            case aria_128_cfb1:
                return "aria-128-cfb1";
            case aria_128_cfb8:
                return "aria-128-cfb8";
            case aria_128_cfb128:
                return "aria-128-cfb128";
            case aria_128_ctr:
                return "aria-128-ctr";
            case aria_128_ofb:
                return "aria-128-ofb";
            case aria_128_gcm:
                return "aria-128-gcm";
            case aria_128_ccm:
                return "aria-128-ccm";
            case aria_192_ecb:
                return "aria-192-ecb";
            case aria_192_cbc:
                return "aria-192-cbc";
            case aria_192_cfb1:
                return "aria-192-cfb1";
            case aria_192_cfb8:
                return "aria-192-cfb8";
            case aria_192_cfb128:
                return "aria-192-cfb128";
            case aria_192_ctr:
                return "aria-192-ctr";
            case aria_192_ofb:
                return "aria-192-ofb";
            case aria_192_gcm:
                return "aria-192-gcm";
            case aria_192_ccm:
                return "aria-192-ccm";
            case aria_256_ecb:
                return "aria-256-ecb";
            case aria_256_cbc:
                return "aria-256-cbc";
            case aria_256_cfb1:
                return "aria-256-cfb1";
            case aria_256_cfb8:
                return "aria-256-cfb8";
            case aria_256_cfb128:
                return "aria-256-cfb128";
            case aria_256_ctr:
                return "aria-256-ctr";
            case aria_256_ofb:
                return "aria-256-ofb";
            case aria_256_gcm:
                return "aria-256-gcm";
            case aria_256_ccm:
                return "aria-256-ccm";
            case camellia_128_ecb:
                return "camellia-128-ecb";
            case camellia_128_cbc:
                return "camellia-128-cbc";
            case camellia_128_cfb1:
                return "camellia-128-cfb1";
            case camellia_128_cfb8:
                return "camellia-128-cfb8";
            case camellia_128_cfb128:
                return "camellia-128-cfb128";
            case camellia_128_ofb:
                return "camellia-128-ofb";
            case camellia_128_ctr:
                return "camellia-128-ctr";
            case camellia_192_ecb:
                return "camellia-192-ecb";
            case camellia_192_cbc:
                return "camellia-192-cbc";
            case camellia_192_cfb1:
                return "camellia-192-cfb1";
            case camellia_192_cfb8:
                return "camellia-192-cfb8";
            case camellia_192_cfb128:
                return "camellia-192-cfb128";
            case camellia_192_ofb:
                return "camellia-192-ofb";
            case camellia_192_ctr:
                return "camellia-192-ctr";
            case camellia_256_ecb:
                return "camellia-256-ecb";
            case camellia_256_cbc:
                return "camellia-256-cbc";
            case camellia_256_cfb1:
                return "camellia-256-cfb1";
            case camellia_256_cfb8:
                return "camellia-256-cfb8";
            case camellia_256_cfb128:
                return "camellia-256-cfb128";
            case camellia_256_ofb:
                return "camellia-256-ofb";
            case camellia_256_ctr:
                return "camellia-256-ctr";
            case chacha20:
                return "chacha20";
            case chacha20_poly1305:
                return "chacha20-poly1305";
            case seed_ecb:
                return "seed-ecb";
            case seed_cbc:
                return "seed-cbc";
            case seed_cfb128:
                return "seed-cfb128";
            case seed_ofb:
                return "seed-ofb";
            case sm4_ecb:
                return "sm4-ecb";
            case sm4_cbc:
                return "sm4-cbc";
            case sm4_cfb128:
                return "sm4-cfb128";
            case sm4_ofb:
                return "sm4-ofb";
            case sm4_ctr:
                return "sm4-ctr";
            case no_cipher:
                return NULL;
        }
        return NULL;
    }

    EC::EC(const char *file_private_key_path, const char *file_public_key_path) {
        load(file_private_key_path, file_public_key_path);
        buildContext();
    }
    
    EC::EC(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format) {
        load(file_private_key_path, private_key_format, file_public_key_path, public_key_format);
        buildContext();
    }

    EC::~EC() {
        clear();
		EVP_MD_CTX_destroy(mdctx);
        BN_CTX_free(bnctx);
    }

    void EC::buildContext() {
		if(! (mdctx = EVP_MD_CTX_create())) {
			throw OpensslException("failed to create EVP_MD context");
		}
    	if(! (bnctx = BN_CTX_new())) {
			throw OpensslException("failed to create BN context");
    	}
    }

    void EC::clear() {
        if(evkey_private) {
            EVP_PKEY_free(evkey_private);
            evkey_private = NULL;
            eckey_private = NULL;
        }
        if(evkey_public) {
            EVP_PKEY_free(evkey_public);
            evkey_public = NULL;
            eckey_public = NULL;
        }
    }

    void EC::load(const char *file_private_key_path, const char *file_public_key_path) {
        if(file_private_key_path) {
        	load_private(file_private_key_path);
        }
        if(file_public_key_path) {
        	load_public(file_public_key_path);
        }
    }
    void EC::load(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format) {
        load_private(file_private_key_path, private_key_format);
        if(file_public_key_path) {
        	load_public(file_public_key_path, public_key_format);
        }
    }
    void EC::load_private(const char *file_private_key_path, file_eckey_format private_key_format, const char *password) {
            
        // clear any active key pair
        clear();

        // auto format detection option
        if(private_key_format == AUTO) {
            private_key_format = getECKEYFormatOfAuto(file_private_key_path);
        }
        // read private key
        FILE *fprv = fopen(file_private_key_path, "r");
        if(fprv == NULL) {
            throw runtime_error("file could not be opened");
        }
        try {
			switch(private_key_format) {
				case PEM:
					if(password == NULL) {
						password = "";
					}
					if(! PEM_read_ECPrivateKey(fprv, &eckey_private, NULL, (void *)password)) {
						throw OpensslException("key could not be read due to invalid file or password");
					}
					break;
				case DER:
					if(! d2i_ECPrivateKey_fp(fprv, &eckey_private)) {
						throw OpensslException("key could not read from the file");
					}
					break;
				default:
					throw invalid_argument("key file format is not supported");
			}
			fclose(fprv);

			// check if key is valid
			if(EC_KEY_check_key(eckey_private) != 1) {
				throw runtime_error("key read was invalid");
			}

			if(! (evkey_private = EVP_PKEY_new()) ||
					EVP_PKEY_assign_EC_KEY(evkey_private, eckey_private) != 1) {
				throw OpensslException("building EVP key failed");
			}
		} catch(...) {
			// discard changes before exit
			if(fprv) {
				fclose(fprv);
			}
			if(evkey_private) {
				EVP_PKEY_free(evkey_private);
				evkey_private = NULL;
			} else {
				EC_KEY_free(eckey_private);
			}
			eckey_private = NULL;
			throw;
		}
    }
    void EC::load_public(const char *file_public_key_path, file_eckey_format public_key_format) {

        // clear previous key  
        if(evkey_public) {
            EVP_PKEY_free(evkey_private);
            evkey_public = NULL;
        }
        eckey_public = NULL;

        // auto format detection option
        if(public_key_format == AUTO) {
            public_key_format = getECKEYFormatOfAuto(file_public_key_path);
        }

        // read public key
        FILE *fpub = fopen(file_public_key_path, "r");
        if(fpub == NULL) {
            throw runtime_error("file could not be opened");
        }
        try {
        	switch(public_key_format) {
				case PEM:
					if(! PEM_read_EC_PUBKEY(fpub, &eckey_public, NULL, NULL)) {
						throw OpensslException("key could not be read from the file");
					}
					break;
				case DER:
					if(! d2i_EC_PUBKEY_fp(fpub, &eckey_public)) {
						throw OpensslException("key could not be read from the file");
					}
					break;
				default:
					throw invalid_argument("key file format is not supported");
			}
			fclose(fpub);

			// check if key is valid
			if(EC_KEY_check_key(eckey_public) != 1) {
				throw runtime_error("key read was invalid");
			}

			if(! (evkey_public = EVP_PKEY_new()) ||
					EVP_PKEY_assign_EC_KEY(evkey_public, eckey_public) != 1) {
				throw OpensslException("building EVP key failed");
			}
        } catch(...) {
			// discard changes before exit
        	if(fpub) {
    			fclose(fpub);
        	}
        	if(evkey_public) {
				EVP_PKEY_free(evkey_public);
				evkey_public = NULL;
			} else {
				EC_KEY_free(eckey_public);
			}
			eckey_public = NULL;
			throw;
        }
    }
    void EC::load(const string &private_key, const string &public_key) {
        load_private(private_key);
        load_public(public_key);
    }
    void EC::load_private(const string &private_key, data_encoding format) {
        
        // clear any active key pair
        clear();

        // decode to bytes array
        string bytes = decoding(private_key, format);

        try {
        	// convert bytes with SubjectPublicKeyInfo format to key
			const unsigned char *bprv = (unsigned char *)bytes.c_str();
			if(! (evkey_private = EVP_PKEY_new()) ||
					! d2i_AutoPrivateKey(&evkey_private, &bprv, bytes.size()) ||
					! (eckey_private = EVP_PKEY_get0_EC_KEY(evkey_private))) {
				throw OpensslException("building key from string failed");
			};

			// check if key is valid
			if(EC_KEY_check_key(eckey_private) != 1) {
				throw runtime_error("key read was invalid");
			}
        } catch(...) {
			// discard changes before exit
        	if(evkey_private) {
    			EVP_PKEY_free(evkey_private);
    			evkey_private = NULL;
        	}
			eckey_private = NULL;
			throw;
        }

    }
    void EC::load_public(const string &public_key, data_encoding format) {
        
        // clear previous key
        if(evkey_public) {
            EVP_PKEY_free(evkey_private);
            evkey_public = NULL;
        }

        // decode to bytes array
        string bytes = decoding(public_key, format);

        try {
			// convert bytes with SubjectPublicKeyInfo format to key
			const unsigned char *bpub = (unsigned char *)bytes.c_str();
			if(! (evkey_public = EVP_PKEY_new()) ||
					! d2i_PUBKEY(&evkey_public, &bpub, bytes.size()) ||
					! (eckey_public = EVP_PKEY_get0_EC_KEY(evkey_public))) {
				throw OpensslException("building key from string failed");
			}

			// check if key is valid
			if(EC_KEY_check_key(eckey_public) != 1) {
				throw runtime_error("key read was invalid");
			}
        } catch(...) {
			// discard changes before exit
        	if(evkey_public) {
    			EVP_PKEY_free(evkey_public);
    			evkey_public = NULL;
        	}
			eckey_public = NULL;
			throw;
        }
    }
    void EC::save(const char *file_private_key_path, const char *file_public_key_path) const {
        save(file_private_key_path, AUTO, file_public_key_path, AUTO);
    }
    void EC::save(const char *file_private_key_path, file_eckey_format private_key_format, const char *file_public_key_path, file_eckey_format public_key_format) const {
        save_private(file_private_key_path, private_key_format);
        save_public(file_public_key_path, public_key_format);
    }
    void EC::save_private(const char *file_private_key_path, file_eckey_format private_key_format, cipher cipher_type, const char *password) const {

        // check if key exist
        if(eckey_private == NULL || evkey_private == NULL) {
            throw runtime_error("key dose not exist");
        }

        // auto format detection option
        if(private_key_format == AUTO) {
            private_key_format = getECKEYFormatOfAuto(file_private_key_path);
        }

        // create output file
        FILE *fprv = fopen(file_private_key_path, "w+");
        if(fprv == NULL) {
            throw runtime_error("file could not be opened");
        }
        EC_KEY_set_asn1_flag(eckey_private, OPENSSL_EC_NAMED_CURVE);
        try {
        	const EVP_CIPHER *cipher = NULL;
			switch(private_key_format) {
				case PEM:
					if(cipher_type != no_cipher && ! (cipher = EVP_get_cipherbyname(cipherToString(cipher_type)))) {
						throw invalid_argument("cipher type is unknown");
					}
					if(PEM_write_ECPrivateKey(fprv, eckey_private, cipher, NULL, 0, NULL, (void *)password) != 1) {
						throw OpensslException("writing key failed");
					}
					break;
				case DER:
					if(i2d_ECPrivateKey_fp(fprv, eckey_private) != 1) {
						throw OpensslException("writing key failed");
					}
					break;
				default:
					throw invalid_argument("private key file format is not supported");
			}
			fclose(fprv);
        } catch(...) {
			fclose(fprv);
        	throw;
        }

    }
    void EC::save_public(const char *file_public_key_path, file_eckey_format public_key_format) const {

        // check if key exist
        if(eckey_public == NULL || evkey_public  == NULL) {
            throw runtime_error("key dose not exist");
        }

        // auto format detection option
        if(public_key_format == AUTO) {
            public_key_format = getECKEYFormatOfAuto(file_public_key_path);
        }

        // create output file
        FILE *fpub = fopen(file_public_key_path, "w+");
        if(fpub == NULL) {
            throw runtime_error("file could not be opened");
        }
        EC_KEY_set_asn1_flag(eckey_public , OPENSSL_EC_NAMED_CURVE);
        try {
			switch(public_key_format) {
				case PEM:
					if(PEM_write_EC_PUBKEY(fpub, eckey_public) != 1) {
						throw OpensslException("writing key failed");
					}
					break;
				case DER:
					if(i2d_EC_PUBKEY_fp(fpub, eckey_public) != 1) {
						throw OpensslException("writing key failed");
					}
					break;
				default:
					throw invalid_argument("private key file format is not supported");
			}
			fclose(fpub);
        } catch(...) {
            fclose(fpub);
            throw;
        }
    }
    const string EC::get_private(data_encoding format) const {
        
        // check if key exist
        if(eckey_private == NULL || evkey_private == NULL) {
            throw runtime_error("key dose not exist");
        }
        
        // convert key to bytes with SubjectPublicKeyInfo format
        size_t max_key_len = 256;
        unsigned char *bpkey_start = (unsigned char *)OPENSSL_malloc(max_key_len);
        if(bpkey_start == NULL) {
			throw OpensslException("failed to allocate bytes buffer");
        }
        unsigned char *bpkey_end = bpkey_start;
        int len = i2d_PrivateKey(evkey_private, &bpkey_end);
        if(len < 0) {
            OPENSSL_free(bpkey_start);
			throw OpensslException("failed to load key to bytes");
        }
        const string &out = encoding(bpkey_start, len, format);
        OPENSSL_free(bpkey_start);
        return out;
    }
    const string EC::get_public(data_encoding format) const {
        
        // check if key exist
        if(eckey_public == NULL || evkey_public == NULL) {
            throw runtime_error("key dose not exist");
        }

        // convert key to bytes with SubjectPublicKeyInfo format
        size_t max_key_len = 256;
        unsigned char *bpkey_start = (unsigned char *)OPENSSL_malloc(max_key_len);
        if(bpkey_start == NULL) {
			throw OpensslException("failed to allocate bytes buffer");
        }
        unsigned char *bpkey_end = bpkey_start;
        int len = i2d_PUBKEY(evkey_public, &bpkey_end);
        if(len < 0) {
            OPENSSL_free(bpkey_start);
			throw OpensslException("failed to load key to bytes");
        }
        const string &out = encoding(bpkey_start, len, format);
        OPENSSL_free(bpkey_start);
        return out;
    }

    const string EC::get_public_point(public_key_point_format form, public_key_point_encoding output) const {

        // check if key exist
        if(eckey_public == NULL || evkey_public  == NULL) {
            throw runtime_error("key dose not exist");
        }

    	const EC_POINT *ppoint = EC_KEY_get0_public_key(eckey_public);
    	const EC_GROUP *group = EC_KEY_get0_group(eckey_public);
    	point_conversion_form_t selected_form;
    	switch(form) {
			case COMPRESSED:
				selected_form = POINT_CONVERSION_COMPRESSED;
				break;
			case UNCOMPRESSED:
				selected_form = POINT_CONVERSION_UNCOMPRESSED;
				break;
			case HYBRID:
				selected_form = POINT_CONVERSION_HYBRID;
				break;
    	}
    	char *x = NULL;
    	size_t length;
    	switch(output) {
			case HEX:
		    	x = EC_POINT_point2hex(group, ppoint, selected_form, bnctx);
		    	if(x == NULL) {
		    		throw OpensslException("Conversion failed");
		    	}
				break;
			case BINARY:
				length = EC_POINT_point2buf(group, ppoint, selected_form, (unsigned char **)&x, bnctx);
		    	if(length == 0) {
		    		throw OpensslException("Conversion failed");
		    	}
				break;
    	}
    	string ret(x);
    	OPENSSL_free(x);
    	return ret;
    }

    void EC::set_public_by_point(const string &pkey, elliptic_curve curve, public_key_point_encoding input) {

        // clear previous key
        if(evkey_public) {
            EVP_PKEY_free(evkey_private);
            evkey_public = NULL;
        }

        if(! (eckey_public = EC_KEY_new_by_curve_name(getEllipticCurveNID(curve)))) {
			throw OpensslException("elliptic curve is not recognize");
        }
    	const EC_GROUP *group = EC_KEY_get0_group(eckey_public);
        EC_POINT *ppoint = EC_POINT_new(group);
    	if(ppoint == NULL) {
			throw OpensslException("failed to create point");
    	}
    	switch(input) {
			case HEX:
		    	if(! EC_POINT_hex2point(group, pkey.c_str(), ppoint, bnctx)) {
		    		throw OpensslException("conversion failed");
		    	}
				break;
			case BINARY:
		    	if(EC_POINT_oct2point(group, ppoint, (const unsigned char *)pkey.c_str(), pkey.size(), bnctx) != 1) {
		    		throw OpensslException("conversion failed");
		    	}
				break;
    	}
        if(EC_KEY_set_public_key(eckey_public, ppoint) != 1) {
    		throw OpensslException("failed to assign point to key");
        }

		// check if key is valid
		if(EC_KEY_check_key(eckey_public) != 1) {
			throw runtime_error("key read was invalid");
		}

		if(! (evkey_public = EVP_PKEY_new()) ||
				EVP_PKEY_assign_EC_KEY(evkey_public, eckey_public) != 1) {
			throw OpensslException("building EVP key failed");
		}

        EC_POINT_free(ppoint);
    }

    void EC::generate_keys(elliptic_curve curve) {
            
        // clear any active key pair
        clear();

        // generate key
        EC_KEY *key = NULL;
        if(! (key = EC_KEY_new_by_curve_name(getEllipticCurveNID(curve)))) {
			throw OpensslException("elliptic curve is not recognize");
        }
        if(EC_KEY_generate_key(key) != 1) {
			throw OpensslException("failed to generate keys pair");
        }
        EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

        // assign
		eckey_private = key;
		if(! (eckey_public = EC_KEY_dup(key)) ||
				! (evkey_private = EVP_PKEY_new()) ||
					! (evkey_public = EVP_PKEY_new()) ||
						EVP_PKEY_assign_EC_KEY(evkey_private, eckey_private) != 1 ||
							EVP_PKEY_assign_EC_KEY(evkey_public, eckey_public) != 1) {
			EC_KEY_free(key);
			eckey_private = NULL;
			eckey_public = NULL;
			EC_KEY_free(eckey_public);
            EVP_PKEY_free(evkey_public);
            evkey_public = NULL;
            EVP_PKEY_free(evkey_private);
            evkey_private = NULL;
			throw OpensslException("failure occur when trying to assign keys");
		}
    }

    void EC::generate_public() {

        // check if key exist
        if(eckey_private == NULL || evkey_private == NULL) {
            throw runtime_error("private key dose not exist");
        }

        // calculate
    	const EC_GROUP *group = EC_KEY_get0_group(eckey_private);
    	const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey_private);
    	EC_POINT *pub_key = EC_POINT_new(group);
        if(EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, bnctx) != 1) {
			throw OpensslException("failed to do point multiplication");
        }

        // assign
        if(EC_KEY_set_public_key(eckey_private, pub_key) != 1 ||
        		! (eckey_public = EC_KEY_dup(eckey_private))) {
			throw OpensslException("failed set public key");
        }
    }

    void EC::sign(hash_types hash, istream &data, ostream &signature) const {
        
        // check if key exist
        if(eckey_private == NULL || evkey_private == NULL) {
            throw runtime_error("private key dose not exist");
        }

        // hash algorithms to use
        const EVP_MD *md;
        switch(hash) {
            case sha1:
                md = EVP_sha1();
                break;
            case sha224:
                md = EVP_sha224();
                break;
            case sha256:
                md = EVP_sha256();
                break;
            case sha384:
                md = EVP_sha384();
                break;
            case sha512:
                md = EVP_sha512();
                break;
            default:
                throw invalid_argument("hash algorithm not supported");
        }
        
        // make signature
		int buffer_size = 256;
		char buffer[buffer_size];
		size_t siglen = 0;
		unsigned char *sig = NULL;
        try {
        	if(EVP_MD_CTX_reset(mdctx) != 1) {
				throw OpensslException("failed to initialize data required for this operation");
        	}

			if(EVP_DigestSignInit(mdctx, NULL, md, NULL, evkey_private) != 1) {
				throw OpensslException("failed to initialize digest operation");
			}

			while(data) {
				data.read(buffer, buffer_size);
				if(EVP_DigestSignUpdate(mdctx, buffer, data.gcount()) != 1) {
					throw OpensslException("failed to make digest operation");
				}
			}

			// signature size
			if(EVP_DigestSignFinal(mdctx, NULL, &siglen) != 1) {
				throw OpensslException("failed to determine signature size");
			}
			sig = (unsigned char *)OPENSSL_malloc(siglen);
			if(sig == NULL) {
				throw OpensslException("failed to allocate signature bytes buffer");
			}
			if(EVP_DigestSignFinal(mdctx, sig, &siglen) != 1) {
				throw OpensslException("failed to generate signature");
			}
	        OPENSSL_free(sig);
        } catch(...) {
        	// free used resources
        	if(sig) {
        		OPENSSL_free(sig);
        	}
        	throw;
        }

        // write signature
        signature.write((const char *)sig, siglen);
    }

    bool EC::verify(hash_types hash, istream &data, istream &signature) const {
        
        // check if key exist
        if(eckey_public == NULL || evkey_public == NULL) {
            throw runtime_error("public key dose not exist");
        }

        // hash algorithms to use
        const EVP_MD *md = NULL;
        switch(hash) {
            case sha1:
                md = EVP_sha1();
                break;
            case sha224:
                md = EVP_sha224();
                break;
            case sha256:
                md = EVP_sha256();
                break;
            case sha384:
                md = EVP_sha384();
                break;
            case sha512:
                md = EVP_sha512();
                break;
            default:
                throw invalid_argument("hash algorithm not supported");
        }

        // read signature
        signature.seekg(0, ios::end);
        size_t siglen = signature.tellg();
		if(siglen == 0) {
			throw OpensslException("failed signature cannot be empty");
		}
        signature.seekg(0, ios::beg);
        unsigned char *sig = (unsigned char *)OPENSSL_malloc(siglen);
		if(sig == NULL) {
			throw OpensslException("failed to allocate signature bytes buffer");
		}
        signature.read((char *) sig, siglen);

        // verify
        int buffer_size = 256;
        char buffer[buffer_size];
        bool ret;

        try {
        	if(EVP_MD_CTX_reset(mdctx) != 1) {
				throw OpensslException("failed to initialize data required for this operation");
        	}

			if(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, evkey_public) != 1) {
				throw OpensslException("failed to initialize digest operation");
			}

			while(data) {
				data.read(buffer, buffer_size);
				if(EVP_DigestVerifyUpdate(mdctx, buffer, data.gcount()) != 1) {
					throw OpensslException("failed to make digest operation");
				}
			}

			if(EVP_DigestVerifyFinal(mdctx, sig, siglen) != 1) {
				ret = false;
			} else {
				ret = true;
			}
			OPENSSL_free(sig);
        } catch(...) {
        	// free used resources
			OPENSSL_free(sig);
        }

        return ret;
    }

}
