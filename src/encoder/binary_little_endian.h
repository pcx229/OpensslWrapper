
#ifndef BINARYLITTLEENDIAN_H_
#define BINARYLITTLEENDIAN_H_

#include <iostream>
using namespace std;

#include "endian_machine.h"

namespace crypto {

	class BinaryLittleEndian : public BlockEncoder {
		public:
			~BinaryLittleEndian();

			/**
			 * a wrapper for Encode() block function
			 * @param data a bytes object to encode
			 * @returns little endian bytes string representing the data
			 */
			bytes Encode(const bytes& data);

			/**
			 * encode the raw data to little endian bytes, if this machine is little
			 * endian base system the data will not be changed, otherwise
			 * the bytes order will be revered.
			 * @param data an array of characters to encode
			 * @param length size of the data array
			 * @returns little endian bytes string representing the data
			 */
			bytes Encode(const unsigned char *data, size_t length);

			/**
			 * decode data from little endian to original bytes, if this machine is little
			 * endian base system the data will not be changed, otherwise
			 * the bytes order will be revered.
			 * @param data little endian encoded bytes
			 * @returns the original raw data this little endian encoded data originated from
			 */
			bytes Decode(const bytes& data);

	};

}

#endif
