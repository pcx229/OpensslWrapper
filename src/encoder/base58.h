
#ifndef BASE58_H_
#define BASE58_H_

#include <iostream>
#include <sstream>
using namespace std;

#include "big_num.h"
#include "encoder.h"

namespace crypto {

	class Base58 : public BlockEncoder {
		public:
			~Base58();

			/**
			 * a wrapper for Encode() block function
			 * @param data a bytes object to encode
			 * @returns a base64 bytes representing the data
			 */
			bytes Encode(const bytes& data);

			/**
			 * encode a raw data to a base58 string using BINARY_BIG_ENDIAN encoding
			 * for converting the data to a big number.
			 * padding of base58 character 0 is added at the beginning for 0 leading bytes.
			 * @param data an array of characters to encode
			 * @param length size of the data array
			 * @returns a base58 string representing the data
			 */
			bytes Encode(const unsigned char *data, size_t length);

			/**
			 * decode a base58 string to the original raw data using BINARY_BIG_ENDIAN encoding
			 * for converting data back to bytes.
			 * @param data a base58 string
			 * @returns the original raw data this base58 string originated from
			 */
			bytes Decode(const bytes& data);
	};

}

#endif /* BASE58_H_ */
