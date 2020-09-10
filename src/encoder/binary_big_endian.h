
#ifndef BINARYBIGENDIAN_H_
#define BINARYBIGENDIAN_H_

#include <iostream>
using namespace std;

#include "endian_machine.h"

namespace crypto {

	class BinaryBigEndian : public BlockEncoder {
		public:
			~BinaryBigEndian();

			/**
			 * a wrapper for Encode() block function
			 * @param data a bytes object to encode
			 * @returns big endian bytes string representing the data
			 */
			bytes Encode(const bytes& data);

			/**
			 * encode the raw data to little endian bytes, if this machine is big
			 * endian base system the data will not be changed, otherwise
			 * the bytes order will be revered.
			 * @param data an array of characters to encode
			 * @param length size of the data array
			 * @returns big endian bytes string representing the data
			 */
			bytes Encode(const unsigned char *data, size_t length);

			/**
			 * decode data from big endian to original bytes, if this machine is big
			 * endian base system the data will not be changed, otherwise
			 * the bytes order will be revered.
			 * @param data big endian encoded bytes
			 * @returns the original raw data this big endian encoded data originated from
			 */
			bytes Decode(const bytes& data);

	};

}

#endif
