#ifndef ENDIAN_MECHINE_H_
#define ENDIAN_MECHINE_H_

#include "encoder.h"

namespace crypto {

	class EndianMachine {
		public:

			/**
			 * get the memory storing endian type of this machine
			 * @return 0 - if little endian, 1 - if big endian
			 */
			static int endian();

			/**
			 * check if this machine is little endian
			 * @return true if it is, otherwise false.
			 */
			static bool isLittleEndian();

			/**
			 * check if this machine is big endian
			 * @return true if it is, otherwise false.
			 */
			static bool isBigEndian();

			/**
			 * reverse the bytes order in the data
			 * @param data an array of bytes to reverse
			 * @param length data array length
			 */
			static bytes filpBytes(const unsigned char *data, size_t length);
	};

}

#endif
