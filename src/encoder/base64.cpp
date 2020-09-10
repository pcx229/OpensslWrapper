
#include "base64.h"

namespace crypto {

	Base64::~Base64() {}

	bytes Base64::Encode(const bytes& data) {
		return Encode((const unsigned char *)data.c_str(), data.size());
	}

	bytes Base64::Encode(const unsigned char *data, size_t length) {
		static const char value2charset[] = {
			'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
			'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
			'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
			'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
			'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
			'w', 'x', 'y', 'z', '0', '1', '2', '3',
			'4', '5', '6', '7', '8', '9', '+', '/'
		};
		// build
		bytesstream ss;
		for(size_t i=0;i<length/3*3;i+=3) {
			ss << value2charset[data[i] >> 2]
				<< value2charset[(data[i] & (char)0x03) << 4 | data[i+1] >> 4]
				<< value2charset[(data[i+1] & (char)0x0f) << 2 | data[i+2] >> 6]
				<< value2charset[data[i+2] & (char)0x3f];
		}
		if(length % 3 == 1) {
			ss << value2charset[data[length-1] >> 2]
				<< value2charset[(data[length-1] & (char)0x03) << 4]
				<< '='
				<< '=';
		} else if(length % 3 == 2) {
			ss << value2charset[data[length-2] >> 2]
				<< value2charset[(data[length-2] & (char)0x03) << 4 | data[length-1] >> 4]
				<< value2charset[(data[length-1] & (char)0x0f) << 2]
				<< '=';
		}
		return ss.str();
	}

	bytes Base64::Decode(const bytes& data) {
		static const char charset2value[] = {
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
			52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
			64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
			15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
			64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
			41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
			64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
		};
		// validate that string is base64
		if(data.size() % 4 != 0) {
			throw invalid_argument("size indicate that this is not a base64 string");
		}
		for(size_t i=0;i<data.size();i++) {
			if((data[i] == '=' && ((i != data.size()-2 && i != data.size()-1) || (data.at(data.size()-1) != '='))) ||
				(data[i] != '=' && charset2value[(unsigned int)data[i]] == 64)) {
				throw invalid_argument("string characters are not one in a valid base64 format");
			}
		}
		// build
		bytesstream ss;
		for(size_t i=0;i<data.size();i+=4) {
			char a = charset2value[(unsigned int)data[i]],
					b = charset2value[(unsigned int)data[i+1]],
					c = charset2value[(unsigned int)data[i+2]],
					d = charset2value[(unsigned int)data[i+3]];
			ss << (char)((a << 2) | ((b & (char)0x30) >> 4));
			if(c != 64) {
				ss << (char)((b << 4) | (c >> 2));
			}
			if(d != 64) {
				ss << (char)((c << 6) | d);
			}
		}
		return ss.str();
	}

}

