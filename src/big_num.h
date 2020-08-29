#ifndef BIGNUM_H_
#define BIGNUM_H_

#include <iostream>
using namespace std;

#include <openssl/bn.h>
#include <openssl/crypto.h>

#include "openssl_exception.h"

namespace crypto {

	/**
	 * this class performs arithmetic operations on integers of arbitrary size.
	 * build on top of the openssl bn library, to make it more easy
	 * writing formulas by using c++ operators overloading.
	 * it uses dynamic memory allocation for storing its data structures.
	 */
	class BigNum {

		BIGNUM *n = NULL;
		BN_CTX *ctx = NULL;

		/**
		 * dynamically allocate data required
		 * @throw OpensslException
		 */
		void init();

	public:

		enum encoding { HEX, DEC, BINARY_LITTLE_ENDIAN, BINARY_BIG_ENDIAN };

		// create a new big integer object

		BigNum();
		BigNum(int i);
		BigNum(long long i);
		// support bytes input encoding BINARY_BIG_ENDIAN and BINARY_LITTLE_ENDIAN
		BigNum(const unsigned char *data, size_t length, encoding input=BINARY_BIG_ENDIAN);
		// support string input encoding HEX and DEC
		BigNum(const char *str, encoding input=DEC);
		BigNum(const BigNum &copy);

		~BigNum();

		BigNum &operator=(const BigNum& b);

		/**
		 * get the value of the current big number assuming that its
		 * smaller then the maximum value of long long, otherwise
		 * return value will have unexpected results.
		 */
		long long operator*() const;

		// comparison

		int compare(const BigNum& v) const;
		bool operator<(const BigNum& b) const;
		bool operator>(const BigNum& b) const;
		bool operator==(const BigNum& b) const;
		bool operator!=(const BigNum& b) const;

		// arithmetic

		void div(const BigNum& a, const BigNum& b, BigNum& div, BigNum& remainder) const;
		BigNum operator/(const BigNum& b) const;
		BigNum operator%(const BigNum& b) const;
		BigNum operator*(const BigNum& b) const;
		BigNum operator+(const BigNum& b) const;
		BigNum operator-(const BigNum& b) const;

		// increment+decrement

		BigNum &operator++(int);
		BigNum &operator--(int);

		// support string output encoding HEX, DEC, BINARY_LITTLE_ENDIAN and BINARY_BIG_ENDIAN
		void print(ostream &os=cout, encoding output=DEC) const;

		// use default print function for the output
		friend ostream &operator<<(ostream &os, const BigNum &n);
	};

}

#endif /* BIGNUM_H_ */
