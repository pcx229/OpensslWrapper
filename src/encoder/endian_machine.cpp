#include "endian_machine.h"

namespace crypto {

	int EndianMachine::endian() {
		unsigned int i = 1;
		char *c = (char*)&i;
		if(*c) {
			return 0; // is little endian
		}
		return 1; // is big endian
	}

	bool EndianMachine::isLittleEndian() {
		return (endian() == 0);
	}

	bool EndianMachine::isBigEndian() {
		return (endian() == 1);
	}

	bytes EndianMachine::filpBytes(const unsigned char *data, size_t length) {
		bytesstream bs;
		while(length > 0) {
			bs << data[--length];
		}
		return bs.str();
	}
}
