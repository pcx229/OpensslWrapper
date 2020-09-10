
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
            case des_cfb:
                return "des-cfb";
            case des_cfb1:
                return "des-cfb1";
            case des_cfb8:
                return "des-cfb8";
            case des_ede_cfb:
                return "des-ede-cfb";
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
            case idea_cfb:
                return "idea-cfb";
            case idea_ofb:
                return "idea-ofb";
            case idea_cbc:
                return "idea-cbc";
            case rc2_cbc:
                return "rc2-cbc";
            case rc2_40_cbc:
                return "rc2-40-cbc";
            case rc2_64_cbc:
                return "rc2-64-cbc";
            case rc2_cfb:
                return "rc2-cfb";
            case rc2_ofb:
                return "rc2-ofb";
            case bf_cbc:
                return "bf-cbc";
            case bf_cfb:
                return "bf-cfb";
            case bf_ofb:
                return "bf-ofb";
            case cast5_cbc:
                return "cast5-cbc";
            case cast5_cfb:
                return "cast5-cfb";
            case cast5_ofb:
                return "cast5-ofb";
            case aes_128_cbc:
                return "aes-128-cbc";
            case aes_128_cfb1:
                return "aes-128-cfb1";
            case aes_128_cfb8:
                return "aes-128-cfb8";
            case aes_128_cfb:
                return "aes-128-cfb";
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
            case aes_128_ocb:
                return "aes-128-ocb";
            case aes_192_cbc:
                return "aes-192-cbc";
            case aes_192_cfb1:
                return "aes-192-cfb1";
            case aes_192_cfb8:
                return "aes-192-cfb8";
            case aes_192_cfb:
                return "aes-192-cfb";
            case aes_192_ofb:
                return "aes-192-ofb";
            case aes_192_ctr:
                return "aes-192-ctr";
            case aes_192_ccm:
                return "aes-192-ccm";
            case aes_192_gcm:
                return "aes-192-gcm";
            case aes_192_ocb:
                return "aes-192-ocb";
            case aes_256_cbc:
                return "aes-256-cbc";
            case aes_256_cfb1:
                return "aes-256-cfb1";
            case aes_256_cfb8:
                return "aes-256-cfb8";
            case aes_256_cfb:
                return "aes-256-cfb";
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
            case aria_128_cbc:
                return "aria-128-cbc";
            case aria_128_cfb1:
                return "aria-128-cfb1";
            case aria_128_cfb8:
                return "aria-128-cfb8";
            case aria_128_cfb:
                return "aria-128-cfb";
            case aria_128_ctr:
                return "aria-128-ctr";
            case aria_128_ofb:
                return "aria-128-ofb";
            case aria_128_gcm:
                return "aria-128-gcm";
            case aria_128_ccm:
                return "aria-128-ccm";
            case aria_192_cbc:
                return "aria-192-cbc";
            case aria_192_cfb1:
                return "aria-192-cfb1";
            case aria_192_cfb8:
                return "aria-192-cfb8";
            case aria_192_cfb:
                return "aria-192-cfb";
            case aria_192_ctr:
                return "aria-192-ctr";
            case aria_192_ofb:
                return "aria-192-ofb";
            case aria_192_gcm:
                return "aria-192-gcm";
            case aria_192_ccm:
                return "aria-192-ccm";
            case aria_256_cbc:
                return "aria-256-cbc";
            case aria_256_cfb1:
                return "aria-256-cfb1";
            case aria_256_cfb8:
                return "aria-256-cfb8";
            case aria_256_cfb:
                return "aria-256-cfb";
            case aria_256_ctr:
                return "aria-256-ctr";
            case aria_256_ofb:
                return "aria-256-ofb";
            case aria_256_gcm:
                return "aria-256-gcm";
            case aria_256_ccm:
                return "aria-256-ccm";
            case camellia_128_cbc:
                return "camellia-128-cbc";
            case camellia_128_cfb1:
                return "camellia-128-cfb1";
            case camellia_128_cfb8:
                return "camellia-128-cfb8";
            case camellia_128_cfb:
                return "camellia-128-cfb";
            case camellia_128_ofb:
                return "camellia-128-ofb";
            case camellia_128_ctr:
                return "camellia-128-ctr";
            case camellia_192_cbc:
                return "camellia-192-cbc";
            case camellia_192_cfb1:
                return "camellia-192-cfb1";
            case camellia_192_cfb8:
                return "camellia-192-cfb8";
            case camellia_192_cfb:
                return "camellia-192-cfb";
            case camellia_192_ofb:
                return "camellia-192-ofb";
            case camellia_192_ctr:
                return "camellia-192-ctr";
            case camellia_256_cbc:
                return "camellia-256-cbc";
            case camellia_256_cfb1:
                return "camellia-256-cfb1";
            case camellia_256_cfb8:
                return "camellia-256-cfb8";
            case camellia_256_cfb:
                return "camellia-256-cfb";
            case camellia_256_ofb:
                return "camellia-256-ofb";
            case camellia_256_ctr:
                return "camellia-256-ctr";
            case chacha20:
                return "chacha20";
            case chacha20_poly1305:
                return "chacha20-poly1305";
            case seed_cbc:
                return "seed-cbc";
            case seed_cfb:
                return "seed-cfb";
            case seed_ofb:
                return "seed-ofb";
            case sm4_cbc:
                return "sm4-cbc";
            case sm4_cfb:
                return "sm4-cfb";
            case sm4_ofb:
                return "sm4-ofb";
            case sm4_ctr:
                return "sm4-ctr";
            case no_cipher:
                return NULL;
        }
        return NULL;
    }
    
    EC::EC(const char *file_private_key_path, file_eckey_format private_key_format) {
    	if(file_private_key_path) {
        	load_private(file_private_key_path, private_key_format);
    	}
        buildContext();
    }

    EC::~EC() {
        clear();
		#ifndef SHARED_CONTEXT
		EVP_MD_CTX_destroy(mdctx);
        BN_CTX_free(bnctx);
		#endif
    }

    void EC::buildContext() {
		#ifndef SHARED_CONTEXT
		if(! (mdctx = EVP_MD_CTX_create())) {
			throw OpensslException("failed to create EVP_MD context");
		}
    	if(! (bnctx = BN_CTX_new())) {
			throw OpensslException("failed to create BN context");
    	}
		#endif
    }

    void EC::clear() {
        if(evkey) {
            EVP_PKEY_free(evkey);
            evkey = NULL;
            eckey = NULL;
            has_private = has_public = false;
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
		switch(private_key_format) {
			case PEM:
				if(password == NULL) {
					password = "";
				}
				if(! PEM_read_ECPrivateKey(fprv, &eckey, NULL, (void *)password)) {
					fclose(fprv);
					throw OpensslException("key could not be read due to invalid file or password");
				}
				break;
			case DER:
				if(! d2i_ECPrivateKey_fp(fprv, &eckey)) {
					fclose(fprv);
					throw OpensslException("key could not read from the file");
				}
				break;
			default:
				fclose(fprv);
				throw invalid_argument("key file format is not supported");
		}
		fclose(fprv);

		// check if key is valid
		if(EC_KEY_check_key(eckey) != 1) {
			EC_KEY_free(eckey);
			eckey = NULL;
			throw OpensslException("key read was invalid");
		}

		// build EV object by EC key
		if(! (evkey = EVP_PKEY_new())) {
			EC_KEY_free(eckey);
			eckey = NULL;
			throw OpensslException("failed to create EVP key");
		}
		if(EVP_PKEY_assign_EC_KEY(evkey, eckey) != 1) {
			EC_KEY_free(eckey);
			EVP_PKEY_free(evkey);
			eckey = NULL;
			evkey = NULL;
			throw OpensslException("failed to assign EC key to EVP key");
		}

		has_private = has_public = true;
    }
    void EC::load_public(const char *file_public_key_path, file_eckey_format public_key_format) {

        // clear previous key
        clear();

        // auto format detection option
        if(public_key_format == AUTO) {
            public_key_format = getECKEYFormatOfAuto(file_public_key_path);
        }

        // read public key
        FILE *fpub = fopen(file_public_key_path, "r");
        if(fpub == NULL) {
            throw runtime_error("file could not be opened");
        }
		switch(public_key_format) {
			case PEM:
				if(! PEM_read_EC_PUBKEY(fpub, &eckey, NULL, NULL)) {
					fclose(fpub);
					throw OpensslException("key could not be read from the file");
				}
				break;
			case DER:
				if(! d2i_EC_PUBKEY_fp(fpub, &eckey)) {
					fclose(fpub);
					throw OpensslException("key could not be read from the file");
				}
				break;
			default:
				fclose(fpub);
				throw invalid_argument("key file format is not supported");
		}
		fclose(fpub);

		// check if key is valid
		if(EC_KEY_check_key(eckey) != 1) {
			EC_KEY_free(eckey);
			eckey = NULL;
			throw runtime_error("key read was invalid");
		}

		// build EV object by EC key
		if(! (evkey = EVP_PKEY_new())) {
			EC_KEY_free(eckey);
			eckey = NULL;
			throw OpensslException("failed to create EVP key");
		}
		if(EVP_PKEY_assign_EC_KEY(evkey, eckey) != 1) {
			EC_KEY_free(eckey);
			EVP_PKEY_free(evkey);
			eckey= NULL;
			evkey = NULL;
			throw OpensslException("failed to assign EC key to EVP key");
		}

		has_public = true;
    }
    void EC::load_private_by_ANS1(const string &private_key, encoders_name format) {
        
        // clear any active key pair
        clear();

        // decode to bytes array
        string bytes = decoding(private_key, format);

		// convert bytes with SubjectPublicKeyInfo format to key
		const unsigned char *bprv = (unsigned char *)bytes.c_str();
		if(! (evkey = EVP_PKEY_new())) {
			throw OpensslException("failed to create EVP key");
		}
		if(! d2i_AutoPrivateKey(&evkey, &bprv, bytes.size())) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
			throw OpensslException("failed converting to EVP key");
		}

		// build EC key by EV object
		if(! (eckey = EVP_PKEY_get0_EC_KEY(evkey))) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
			throw OpensslException("failed to assign EC key");
		}

		// check if key is valid
		if(EC_KEY_check_key(eckey) != 1) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
			eckey = NULL;
			throw OpensslException("key read was invalid");
		}

		has_private = has_public = true;
    }
    void EC::load_public_by_ANS1(const string &public_key, encoders_name format) {

        // clear any active key pair
        clear();

        // decode to bytes array
        string bytes = decoding(public_key, format);

		// convert bytes with SubjectPublicKeyInfo format to key
		const unsigned char *bpub = (unsigned char *)bytes.c_str();
		if(! (evkey = EVP_PKEY_new())) {
			throw OpensslException("failed to create EVP key");
		}
		if(! d2i_PUBKEY(&evkey, &bpub, bytes.size())) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
			throw OpensslException("failed converting to EVP key");
		}

		// build EC key by EV object
		if(! (eckey = EVP_PKEY_get0_EC_KEY(evkey))) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
			throw OpensslException("failed to assign EC key");
		}

		// check if key is valid
		if(EC_KEY_check_key(eckey) != 1) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
			eckey = NULL;
			throw runtime_error("key read was invalid");
		}

		has_public = true;
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
    	if(! has_private) {
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
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);
		const EVP_CIPHER *cipher = NULL;
		switch(private_key_format) {
			case PEM:
				if(cipher_type != no_cipher && ! (cipher = EVP_get_cipherbyname(cipherToString(cipher_type)))) {
					fclose(fprv);
					throw invalid_argument("cipher type is unknown");
				}
				if(PEM_write_ECPrivateKey(fprv, eckey, cipher, NULL, 0, NULL, (void *)password) != 1) {
					fclose(fprv);
					throw OpensslException("writing key failed");
				}
				break;
			case DER:
				if(i2d_ECPrivateKey_fp(fprv, eckey) != 1) {
					fclose(fprv);
					throw OpensslException("writing key failed");
				}
				break;
			default:
				fclose(fprv);
				throw invalid_argument("private key file format is not supported");
		}
		fclose(fprv);
    }
    void EC::save_public(const char *file_public_key_path, file_eckey_format public_key_format) const {

        // check if key exist
    	if(! has_public) {
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
        EC_KEY_set_asn1_flag(eckey , OPENSSL_EC_NAMED_CURVE);
		switch(public_key_format) {
			case PEM:
				if(PEM_write_EC_PUBKEY(fpub, eckey) != 1) {
					fclose(fpub);
					throw OpensslException("writing key failed");
				}
				break;
			case DER:
				if(i2d_EC_PUBKEY_fp(fpub, eckey) != 1) {
					fclose(fpub);
					throw OpensslException("writing key failed");
				}
				break;
			default:
				fclose(fpub);
				throw invalid_argument("private key file format is not supported");
		}
		fclose(fpub);
    }
    const string EC::get_private_number(encoders_name format) const {

        // check if key exist
    	if(! has_private) {
            throw runtime_error("key dose not exist");
    	}

        // get the private key as a number
        const BIGNUM *key = EC_KEY_get0_private_key(eckey);
		int nbytes = BN_num_bytes(key);
		unsigned char *data = (unsigned char *)OPENSSL_malloc(nbytes);
        if(data == NULL) {
			throw OpensslException("failed to allocate bytes buffer");
        }
		if(BN_bn2lebinpad(key, data, nbytes) < 0) {
			OPENSSL_free(data);
			throw OpensslException("conversion failed");
        }
        const string &out = encoding((const unsigned char *)data, nbytes, format);
		OPENSSL_free(data);
		return out;
    }
    const string EC::get_private_ANS1(encoders_name format) const {
        
        // check if key exist
    	if(! has_private) {
            throw runtime_error("key dose not exist");
    	}
        
        // convert key to bytes with ASN.1 DER format
        size_t max_key_len = 256;
        unsigned char *bpkey_start = (unsigned char *)OPENSSL_malloc(max_key_len);
        if(bpkey_start == NULL) {
			throw OpensslException("failed to allocate bytes buffer");
        }
        unsigned char *bpkey_end = bpkey_start;
        int len = i2d_PrivateKey(evkey, &bpkey_end);
        if(len <= 0) {
            OPENSSL_free(bpkey_start);
			throw OpensslException("failed to load key to bytes");
        }
        const string &out = encoding(bpkey_start, len, format);
        OPENSSL_free(bpkey_start);
        return out;
    }
    const string EC::get_public_ANS1(encoders_name format) const {
        
        // check if key exist
    	if(! has_public) {
            throw runtime_error("key dose not exist");
    	}

        // convert key to bytes with ASN.1 DER format
        size_t max_key_len = 256;
        unsigned char *bpkey_start = (unsigned char *)OPENSSL_malloc(max_key_len);
        if(bpkey_start == NULL) {
			throw OpensslException("failed to allocate bytes buffer");
        }
        unsigned char *bpkey_end = bpkey_start;
        int len = i2d_PUBKEY(evkey, &bpkey_end);
        if(len < 0) {
            OPENSSL_free(bpkey_start);
			throw OpensslException("failed to load key to bytes");
        }
        const string &out = encoding(bpkey_start, len, format);
        OPENSSL_free(bpkey_start);
        return out;
    }

    const string EC::get_public_point(public_key_point_format form, encoders_name output) const {

        // check if key exist
    	if(! has_public) {
            throw runtime_error("key dose not exist");
    	}

    	const EC_POINT *ppoint = EC_KEY_get0_public_key(eckey);
    	const EC_GROUP *group = EC_KEY_get0_group(eckey);
    	point_conversion_form_t selected_form;
    	switch(form) {
			case COMPRESSED:
				selected_form = point_conversion_form_t::POINT_CONVERSION_COMPRESSED;
				break;
			case UNCOMPRESSED:
				selected_form = point_conversion_form_t::POINT_CONVERSION_UNCOMPRESSED;
				break;
			case HYBRID:
				selected_form = point_conversion_form_t::POINT_CONVERSION_HYBRID;
				break;
    	}
    	unsigned char *x = NULL;
    	size_t length;
		length = EC_POINT_point2buf(group, ppoint, selected_form, (unsigned char **)&x, bnctx);
    	if(length == 0) {
    		throw OpensslException("conversion failed");
    	}
        const string &out = encoding(x, length, output);
    	OPENSSL_free(x);
    	return out;
    }

    void EC::load_private_by_number(const string &private_key_number, elliptic_curve curve, encoders_name input) {

        // clear any active key pair
        clear();

        // build the key by a number
        if(! (eckey = EC_KEY_new_by_curve_name(getEllipticCurveNID(curve)))) {
			throw OpensslException("elliptic curve is not recognize");
        }
    	BIGNUM *number = BN_new();
    	if(number == NULL) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to create number");
    	}
    	switch(input) {
			case HEX:
		    	if(BN_hex2bn(&number, private_key_number.c_str()) == 0) {
		    		BN_free(number);
		    		EC_KEY_free(eckey);
		    		eckey = NULL;
		    		throw OpensslException("conversion failed");
		    	}
				break;
			case BINARY:
		    	if(! BN_lebin2bn((const unsigned char *)private_key_number.c_str(), private_key_number.size(), number)) {
		    		BN_free(number);
		    		EC_KEY_free(eckey);
		    		eckey = NULL;
		    		throw OpensslException("conversion failed");
		    	}
				break;
			default:
	    		BN_free(number);
	    		EC_KEY_free(eckey);
	    		eckey = NULL;
				throw invalid_argument("input format is not supported");
    	}
        if(EC_KEY_set_private_key(eckey, number) != 1) {
    		BN_free(number);
    		EC_KEY_free(eckey);
    		eckey = NULL;
        	throw OpensslException("failed to assign number to key");
        }
		BN_free(number);
    	EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

        // generate public part
    	const EC_GROUP *group = EC_KEY_get0_group(eckey);
    	const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);
    	EC_POINT *pub_key = EC_POINT_new(group);
    	if(group == NULL || priv_key == NULL || pub_key == NULL) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to get required values for public key generation");
    	}
        if(EC_POINT_mul(group, pub_key, priv_key, NULL, NULL, bnctx) != 1) {
        	EC_POINT_free(pub_key);
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to do point multiplication");
        }

        // assign public key
        if(EC_KEY_set_public_key(eckey, pub_key) != 1) {
        	EC_POINT_free(pub_key);
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to set public key");
        }
    	EC_POINT_free(pub_key);

    	// check if the key is valid
		if(EC_KEY_check_key(eckey) != 1) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
    		throw OpensslException("key read was invalid");
		}

		// build EV object by EC key
		if(! (evkey = EVP_PKEY_new())) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to create EVP key");
		}
		if(EVP_PKEY_assign_EC_KEY(evkey, eckey) != 1) {
			EVP_PKEY_free(evkey);
    		eckey = NULL;
			evkey = NULL;
			throw OpensslException("building EVP key failed");
		}

		has_private = has_public = true;
    }

    void EC::load_public_by_point(const string &public_key_point, elliptic_curve curve, encoders_name input) {

        // clear previous key
        clear();

        // build the key
        if(! (eckey = EC_KEY_new_by_curve_name(getEllipticCurveNID(curve)))) {
			throw OpensslException("elliptic curve is not recognize");
        }
    	const EC_GROUP *group = EC_KEY_get0_group(eckey);
        EC_POINT *ppoint = EC_POINT_new(group);
    	if(ppoint == NULL) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to create point");
    	}
    	switch(input) {
			case HEX:
		    	if(! EC_POINT_hex2point(group, public_key_point.c_str(), ppoint, bnctx)) {
		    		EC_POINT_free(ppoint);
		    		EC_KEY_free(eckey);
		    		eckey = NULL;
		    		throw OpensslException("conversion failed");
		    	}
				break;
			case BINARY:
		    	if(EC_POINT_oct2point(group, ppoint, (const unsigned char *)public_key_point.c_str(), public_key_point.size(), bnctx) != 1) {
		    		EC_POINT_free(ppoint);
		    		EC_KEY_free(eckey);
		    		eckey = NULL;
		    		throw OpensslException("conversion failed");
		    	}
				break;
			default:
				EC_POINT_free(ppoint);
	    		EC_KEY_free(eckey);
	    		eckey = NULL;
				throw invalid_argument("input format is not supported");
    	}

    	// assign to EC object
        if(EC_KEY_set_public_key(eckey, ppoint) != 1) {
        	EC_POINT_free(ppoint);
    		EC_KEY_free(eckey);
    		eckey = NULL;
        	throw OpensslException("failed to assign point to key");
        }
        EC_POINT_free(ppoint);

		// check if key is valid
		if(EC_KEY_check_key(eckey) != 1) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
    		throw OpensslException("key read was invalid");
		}

		// build EV object by EC key
		if(! (evkey = EVP_PKEY_new())) {
    		EC_KEY_free(eckey);
    		eckey = NULL;
			throw OpensslException("failed to create EVP key");
		}
		if(EVP_PKEY_assign_EC_KEY(evkey, eckey) != 1) {
			EVP_PKEY_free(evkey);
			evkey = NULL;
    		eckey = NULL;
			throw OpensslException("building EVP key failed");
		}

		has_public = true;
    }

    void EC::generate_keys(elliptic_curve curve) {
            
        // clear any active key pair
        clear();

        // generate key
        if(! (eckey = EC_KEY_new_by_curve_name(getEllipticCurveNID(curve)))) {
			throw OpensslException("elliptic curve is not recognize");
        }
        if(EC_KEY_generate_key(eckey) != 1) {
        	EC_KEY_free(eckey);
			eckey = NULL;
			throw OpensslException("failed to generate keys pair");
        }
        EC_KEY_set_asn1_flag(eckey, OPENSSL_EC_NAMED_CURVE);

		// build EV object by EC key
		if(! (evkey = EVP_PKEY_new())) {
			EC_KEY_free(eckey);
			eckey = NULL;
			throw OpensslException("failed to create EVP key");
		}
		if(EVP_PKEY_assign_EC_KEY(evkey, eckey) != 1) {
			EVP_PKEY_free(evkey);
			EC_KEY_free(eckey);
			eckey = NULL;
			evkey = NULL;
			throw OpensslException("failed assign EC key to EVP key");
		}

		has_private = has_public = true;
    }

    void EC::sign(hash_types hash, istream &data, ostream &signature) const {
        
        // check if key exist
    	if(! has_private) {
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


		#ifdef SHARED_CONTEXT
		mdctx.lock();
		#endif
		if(EVP_MD_CTX_reset(mdctx) != 1) {
			throw OpensslException("failed to initialize data required for this operation");
		}

		if(EVP_DigestSignInit(mdctx, NULL, md, NULL, evkey) != 1) {
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
			OPENSSL_free(sig);
			throw OpensslException("failed to generate signature");
		}
		#ifdef SHARED_CONTEXT
		mdctx.unlock();
		#endif
		OPENSSL_free(sig);

        // write signature
        signature.write((const char *)sig, siglen);
    }

    bool EC::verify(hash_types hash, istream &data, istream &signature) const {
        
        // check if key exist
    	if(! has_public) {
            throw runtime_error("private key dose not exist");
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

		#ifdef SHARED_CONTEXT
		mdctx.lock();
		#endif
		if(EVP_MD_CTX_reset(mdctx) != 1) {
			OPENSSL_free(sig);
			throw OpensslException("failed to initialize data required for this operation");
		}

		if(EVP_DigestVerifyInit(mdctx, NULL, md, NULL, evkey) != 1) {
			OPENSSL_free(sig);
			throw OpensslException("failed to initialize digest operation");
		}

		while(data) {
			data.read(buffer, buffer_size);
			if(EVP_DigestVerifyUpdate(mdctx, buffer, data.gcount()) != 1) {
				OPENSSL_free(sig);
				throw OpensslException("failed to make digest operation");
			}
		}

		if(EVP_DigestVerifyFinal(mdctx, sig, siglen) != 1) {
			ret = false;
		} else {
			ret = true;
		}
		#ifdef SHARED_CONTEXT
		mdctx.unlock();
		#endif
		OPENSSL_free(sig);

        return ret;
    }

}
