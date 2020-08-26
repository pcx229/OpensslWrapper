#include "Base58.h"

namespace crypto {

	template<typename T>
	static void reverse(T beg, T end) {
		while(beg != end-- && beg != end) {
			swap(*beg, *end);
			beg++;
		}
	}

	string Base58::Encode(const unsigned char *data, size_t length) {
		static const char value2charset[] = {
			'1', '2', '3', '4', '5', '6', '7', '8',
			'9', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
			'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q',
			'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y',
			'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g',
			'h', 'i', 'j', 'k', 'm', 'n', 'o', 'p',
			'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
			'y', 'z'
		};
		// check for leading zeros
		int leading_zeros = 0;
		for(size_t i=0;i<length;i++) {
			if(data[i] == 0) {
				leading_zeros++;
			} else {
				break;
			}
		}
		BigNum n(data, length, BigNum::BINARY_BIG_ENDIAN);
		stringstream reversed_base58;
		while(n > 0) {
			BigNum d, r;
			n.div(n, 58, d, r);
			reversed_base58 << value2charset[*r];
			n = d;
		}
		// add leading zeros
		while(leading_zeros--) {
			reversed_base58 << value2charset[0];
		}
		string base58 = reversed_base58.str();
		reverse(base58.begin(), base58.end());
		return base58;
	}

	string Base58::Decode(const string& data) {
		static const char charset2value[] = {
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58,  0,  1,  2,  3,  4,  5,  6,  7,  8, 58, 58, 58, 58, 58, 58,
			58,  9, 10, 11, 12, 13, 14, 15, 16, 58, 17, 18, 19, 20, 21, 58,
			22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 58, 58, 58, 58, 58,
			58, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 58, 44, 45, 46,
			47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58,
			58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58, 58
		};
		BigNum n = 0;
		stringstream ss;
		string::const_iterator it = data.begin(), end = data.end();
		// add leading zeros
		while(it != end) {
			int c = (int)charset2value[(int)*it];
			if(c == 0) {
				ss << (char)0;
			} else {
				break;
			}
			it++;
		}
		while(it != end) {
			int c = (int)charset2value[(int)*it];
			n = n * 58 + c;
			it++;
		}
		n.print(ss, BigNum::BINARY_BIG_ENDIAN);
		return ss.str();
	}
}
