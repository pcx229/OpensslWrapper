
#ifndef _BASE64_H_
#define _BASE64_H_

#include <sstream>
#include <iostream>
using namespace std;

#include "encoder.h"

namespace crypto {

	class Base64 : public BlockEncoder {
		public:
			~Base64();

			/**
			 * a wrapper for Encode() block function
			 * @param data a bytes object to encode
			 * @returns a base64 bytes representing the data
			 */
			bytes Encode(const bytes& data);

			/**
			 * encode a raw data to a base64 bytes
			 * @param data an array of characters to encode
			 * @param length size of the data array
			 * @returns a base64 bytes representing the data
			 */
			bytes Encode(const unsigned char *data, size_t length);

			/**
			 * decode a base64 bytes to the original raw data
			 * @param data a base64 bytes
			 * @returns the original raw data this base64 bytes originated from
			 * @throw invalid_argument exception if the data is not a valid base64 string
			 */
			bytes Decode(const bytes& data);
	};

}

#endif /* _BASE64_H_ */
