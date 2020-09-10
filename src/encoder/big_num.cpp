
#include "big_num.h"

namespace crypto {

	void BigNum::init() {
		n = BN_new();
		#ifndef SHARED_CONTEXT
		ctx = BN_CTX_new();
		#endif
		if(!n || !ctx) {
			throw OpensslException("failed to initialize data");
		}
	}

	BigNum::BigNum() {
		init();
	}
	BigNum::BigNum(int i) {
		init();
		if(BN_set_word(n, abs(i)) != 1) {
			throw OpensslException("failed to assign value");
		}
		BN_set_negative(n, i<0);
	}
	BigNum::BigNum(long long i) {
		init();
		if(BN_set_word(n, abs(i)) != 1) {
			throw OpensslException("failed to assign value");
		}
		BN_set_negative(n, i<0);
	}
	BigNum::BigNum(const unsigned char *data, size_t length, encoding input) {
		init();
		switch(input) {
			case BINARY_BIG_ENDIAN:
				if(! BN_bin2bn(data, length, n)) {
					throw OpensslException("failed to assign value");
				}
				break;
			case BINARY_LITTLE_ENDIAN:
				if(! BN_lebin2bn(data, length, n)) {
					throw OpensslException("failed to assign value");
				}
				break;
			default:
				throw invalid_argument("input encoding is not recognized");
		}
	}
	BigNum::BigNum(const char *str, encoding input) {
		init();
		switch(input) {
			case HEX:
				if(BN_hex2bn(&n, str) == 0) {
					throw OpensslException("failed to assign value");
				}
				break;
			case DEC:
				if(BN_dec2bn(&n, str) == 0) {
					throw OpensslException("failed to assign value");
				}
				break;
			default:
				throw invalid_argument("input encoding is not recognized");
		}
	}
	BigNum::BigNum(const BigNum &copy) {
		init();
		if(! BN_copy(n, copy.n)) {
			throw OpensslException("failed to copy other number state");
		}
	}
	BigNum::~BigNum() {
		BN_free(n);
		#ifndef SHARED_CONTEXT
		BN_CTX_free(ctx);
		#endif
	}
	BigNum &BigNum::operator=(const BigNum& b) {
		if(! BN_copy(n, b.n)) {
			throw OpensslException("failed to copy other number state");
		}
		return *this;
	}
	int BigNum::compare(const BigNum& v) const {
		return BN_cmp(n, v.n);
	}
	bool BigNum::operator<(const BigNum& b) const {
		return compare(b) < 0;
	}
	bool BigNum::operator>(const BigNum& b) const {
		return compare(b) > 0;
	}
	bool BigNum::operator==(const BigNum& b) const {
		return compare(b) == 0;
	}
	bool BigNum::operator!=(const BigNum& b) const {
		return compare(b) != 0;
	}
	void BigNum::div(const BigNum& a, const BigNum& b, BigNum& div, BigNum& remainder) const {
		BN_div(div.n, remainder.n, a.n, b.n, ctx);
	}
	long BigNum::operator*() const {
		return BN_get_word(n) * (BN_is_negative(n) ? -1 : 1);
	}
	BigNum BigNum::operator/(const BigNum& b) const {
		BigNum d;
		BN_div(d.n, NULL, n, b.n, ctx);
		return d;
	}
	BigNum BigNum::operator%(const BigNum& b) const {
		BigNum r;
		BN_div(NULL, r.n, n, b.n, ctx);
		return r;
	}
	BigNum BigNum::operator*(const BigNum& b) const {
		BigNum r;
		BN_mul(r.n, n, b.n, ctx);
		return r;
	}
	BigNum BigNum::operator+(const BigNum& b) const {
		BigNum r;
		BN_add(r.n, n, b.n);
		return r;
	}
	BigNum BigNum::operator-(const BigNum& b) const {
		BigNum r;
		BN_sub(r.n, n, b.n);
		return r;
	}
	BigNum &BigNum::operator++(int) {
		BN_add(n, n, BigNum(1).n);
		return *this;
	}
	BigNum &BigNum::operator--(int) {
		BN_sub(n, n, BigNum(1).n);
		return *this;
	}
	void BigNum::print(ostream &os, encoding output) const {
		switch(output) {
			case HEX:
				{
					char *hex = BN_bn2hex(n);
					if(hex == NULL) {
						OPENSSL_free(hex);
						throw OpensslException("conversion failed");
			        }
					os << hex;
					OPENSSL_free(hex);
				}
				break;
			case DEC:
				{
					char *dec = BN_bn2dec(n);
					if(dec == NULL) {
						OPENSSL_free(dec);
						throw OpensslException("conversion failed");
			        }
					os << dec;
					OPENSSL_free(dec);
				}
				break;
			case BINARY_LITTLE_ENDIAN:
				{
					int nbytes = BN_num_bytes(n);
					unsigned char *data = (unsigned char *)OPENSSL_malloc(nbytes);
					if(BN_bn2lebinpad(n, data, nbytes) < 0) {
						OPENSSL_free(data);
						throw OpensslException("conversion failed");
			        }
					os.write((char *)data, nbytes);
					OPENSSL_free(data);
				}
				break;
			case BINARY_BIG_ENDIAN:
				{
					int nbytes = BN_num_bytes(n);
					unsigned char *data = (unsigned char *)OPENSSL_malloc(nbytes);
					if(BN_bn2binpad(n, data, nbytes) < 0) {
						OPENSSL_free(data);
						throw OpensslException("conversion failed");
			        }
					os.write((char *)data, nbytes);
					OPENSSL_free(data);
				}
				break;
			default:
				throw invalid_argument("output encoding is not recognized");
		}
	}
	ostream &operator<<(ostream &os, const BigNum &n) {
		n.print(os);
		return os;
	}
}
