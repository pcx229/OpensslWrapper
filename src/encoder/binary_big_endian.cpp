
#include "binary_big_endian.h"

namespace crypto {

	BinaryBigEndian::~BinaryBigEndian() {}

	bytes BinaryBigEndian::Encode(const bytes& data) {
		return Encode((const unsigned char *)data.c_str(), data.size());
	}

	bytes BinaryBigEndian::Encode(const unsigned char *data, size_t length) {
		return EndianMachine::isBigEndian() ? bytes((const char *)data, length) : EndianMachine::filpBytes(data, length);
	}

	bytes BinaryBigEndian::Decode(const bytes& data) {
		return EndianMachine::isBigEndian() ? data : EndianMachine::filpBytes((const unsigned char *)data.c_str(), data.size());
	}
}
