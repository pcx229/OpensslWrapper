
#ifndef _BASE64_H_
#define _BASE64_H_

#include <sstream>
#include <iostream>
using namespace std;

namespace crypto {

	class Base64 {
		public:

			/**
			 * encode a raw data to a base64 string
			 * @param data an array of characters to encode
			 * @param length size of the data array
			 * @returns a base64 string representing the data
			 */
			static string Encode(const unsigned char *data, size_t length);

			/**
			 * decode a base64 string to the original raw data
			 * @param data a base64 string
			 * @returns the original raw data this base64 string originated from
			 * @throw invalid_argument exception if the data is not a valid base64 string
			 */
			static string Decode(const string& data);
	};

}

#endif /* _BASE64_H_ */
