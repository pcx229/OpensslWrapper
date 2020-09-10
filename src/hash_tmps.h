
#include "hash.h"

namespace crypto {

	template <hash_types type>
    void Hash<type>::init() {

        const EVP_MD *md = EVP_get_digestbyname(getHashTypeString(type));
        if (!md) {
            throw invalid_argument("unknown message digest hash type");
        }

		#ifndef SHARED_CONTEXT
        mdctx = EVP_MD_CTX_create();
        if(!mdctx) {
        	throw OpensslException("failed to create MD context");
        }
		#endif

		#ifdef SHARED_CONTEXT
        mdctx.lock();
		#endif
        if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        	throw OpensslException("failed to initialize hash algorithm");
        }
    }

    template <hash_types type>
    Hash<type>::Hash() {
        init();
    }

    template <hash_types type>
    Hash<type>::Hash(const string &data, encoders_name input) {
        init();
        update(data, input);
    }

    template <hash_types type>
    Hash<type>::Hash(istream &data, encoders_name input) {
        init();
        update(data, input);
    }

    template <hash_types type>
    Hash<type>::Hash(const Hash<type> &other) {
        this->operator=(other);
    }

    template <hash_types type>
    Hash<type>::~Hash() {
		#ifdef SHARED_CONTEXT
        mdctx.unlock();
		#else
        if(mdctx != NULL) {
            EVP_MD_CTX_destroy(mdctx);
        }
		#endif
    }

    template <hash_types type>
    Hash<type> &Hash<type>::operator=(const Hash<type> &other) {
		#ifdef SHARED_CONTEXT
    	mdctx = other.mdctx;
		#else
        if(EVP_MD_CTX_copy(mdctx, other.mdctx) != 1) {
        	throw OpensslException("failed to copy source hash to destination hash");
        }
		#endif
        if(other.is_over) {
            is_over = true;
            strncpy((char*)md_value, (const char*)other.md_value, other.md_len);
            md_len = other.md_len;
        }
        return *this;
    }

    template <hash_types type>
    Hash<type> &Hash<type>::update(const string &data, encoders_name input) {
        if(is_over) {
            throw logic_error("cannot make updates after digest operation");
        }
        const string &dec = decoding(data, input);
        if(EVP_DigestUpdate(mdctx, dec.c_str(), dec.size()) != 1) {
        	throw OpensslException("failed make hash digest operation");
        }
        return *this;
    }

    template <hash_types type>
    Hash<type> &Hash<type>::operator<<(const string &data) {
        return update(data);
    }

    template <hash_types type>
    Hash<type> &Hash<type>::update(istream &data, encoders_name input) {
        if(is_over) {
            throw logic_error("cannot make updates after digest operation");
        }
        int buffer_size = 256;
        char buffer[buffer_size];
        while(data) {
            data.read(buffer, buffer_size);
            const string &dec = decoding((unsigned char *)buffer, data.gcount(), input);
            if(EVP_DigestUpdate(mdctx, dec.c_str(), dec.size()) != 1) {
            	throw OpensslException("failed make hash digest operation");
            }
        }
        return *this;
    }

    template <hash_types type>
    Hash<type> &Hash<type>::operator<<(istream &data) {
        return update(data);
    }

    template <hash_types type>
    string Hash<type>::digest(encoders_name enc) {
        if(!is_over) {
            if(EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
            	throw OpensslException("failed to generate hash");
            }
            is_over = true;
			#ifdef SHARED_CONTEXT
            mdctx.unlock();
			#endif
        }
        return encoding(md_value, md_len, enc);
    }

    template <hash_types type>
    Hash<type>::operator string() const {
        return const_cast<Hash<type>*>(this)->digest();
    }

    template <hash_types type>
    bool Hash<type>::operator==(const string &str) {
    	string lowers(str.size(), '#');
    	transform(str.begin(), str.end(), lowers.begin(), ::tolower);
    	return string(*this) == lowers;
    }

    template <hash_types type>
    ostream &operator<<(ostream &os, const Hash<type> &hs) {
        os << const_cast<Hash<type>*>(&hs)->digest();
        return os;
    }
    
}
