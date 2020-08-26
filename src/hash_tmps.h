
namespace crypto {

	template <hash_types type>
    void Hash<type>::init() {

        const EVP_MD *md = EVP_get_digestbyname(getHashTypeString(type));
        if (!md) {
            throw invalid_argument("Unknown message digest hash type");
        }

        mdctx = EVP_MD_CTX_create();
        if(!mdctx) {
        	throw OpensslException("Failed to create MD context");
        }

        if(EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        	throw OpensslException("Failed to initialize hash algorithm");
        }
    }

    template <hash_types type>
    Hash<type>::Hash() {
        init();
    }

    template <hash_types type>
    Hash<type>::Hash(const string &data) {
        init();
        update(data);
    }

    template <hash_types type>
    Hash<type>::Hash(istream &data) {
        init();
        update(data);
    }

    template <hash_types type>
    Hash<type>::Hash(const Hash<type> &other) {
        this->operator=(other);
    }

    template <hash_types type>
    Hash<type>::~Hash() {
        if(mdctx != NULL) {
            EVP_MD_CTX_destroy(mdctx);
        }
    }

    template <hash_types type>
    Hash<type> &Hash<type>::operator=(const Hash<type> &other) {
        if(EVP_MD_CTX_copy(mdctx, other.mdctx) != 1) {
        	throw OpensslException("Failed to copy source hash to destination hash");
        }
        if(other.is_over) {
            is_over = true;
            strncpy((char*)md_value, (const char*)other.md_value, other.md_len);
            md_len = other.md_len;
        }
        return *this;
    }

    template <hash_types type>
    Hash<type> &Hash<type>::update(const string &data) {
        if(is_over) {
            throw logic_error("Cannot make updates after digest operation");
        }
        if(EVP_DigestUpdate(mdctx, data.c_str(), data.size()) != 1) {
        	throw OpensslException("Failed make hash digest operation");
        }
        return *this;
    }

    template <hash_types type>
    Hash<type> &Hash<type>::operator<<(const string &data) {
        return update(data);
    }

    template <hash_types type>
    Hash<type> &Hash<type>::update(istream &data) {
        if(is_over) {
            throw logic_error("Cannot make updates after digest operation");
        }
        int buffer_size = 256;
        char buffer[buffer_size];
        while(data) {
            data.read(buffer, buffer_size);
            if(EVP_DigestUpdate(mdctx, buffer, data.gcount()) != 1) {
            	throw OpensslException("Failed make hash digest operation");
            }
        }
        return *this;
    }

    template <hash_types type>
    Hash<type> &Hash<type>::operator<<(istream &data) {
        return update(data);
    }

    template <hash_types type>
    string Hash<type>::digest(data_encoding enc) {
        if(!is_over) {
            if(EVP_DigestFinal_ex(mdctx, md_value, &md_len) != 1) {
            	throw OpensslException("Failed to generate hash");
            }
            is_over = true;
        }
        return encoding(md_value, md_len, enc);
    }

    template <hash_types type>
    Hash<type>::operator string() const {
        return const_cast<Hash<type>*>(this)->digest();
    }

    template <hash_types type>
    ostream &operator<<(ostream &os, const Hash<type> &hs) {
        os << const_cast<Hash<type>*>(&hs)->digest();
        return os;
    }
    
}
