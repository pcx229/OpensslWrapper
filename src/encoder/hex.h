
#ifndef _HEX_H_
#define _HEX_H_

#include <sstream>
#include <iomanip>
#include <iostream>
using namespace std;

#include "encoder.h"

namespace crypto {

	class Hex : public BlockEncoder {
		public:
			~Hex();

			/**
			 * a wrapper for Encode() block function
			 * @param data a bytes object to encode
			 * @returns a hex bytes representing the data
			 */
			bytes Encode(const bytes& data);

			/**
			 * encode a raw data to a hex bytes
			 * @param data an array of characters to encode
			 * @param length size of the data array
			 * @returns a hex bytes representing the data
			 */
			bytes Encode(const unsigned char *data, size_t length);

			/**
			 * decode a hex bytes to the original raw data
			 * @param data a hex bytes
			 * @returns the original raw data the this hex bytes representing
			 * @throw invalid_argument exception if the data is not a valid hex string
			 */
			bytes Decode(const bytes& data);
	};

}

#endif
