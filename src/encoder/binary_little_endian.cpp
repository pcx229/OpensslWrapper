
#include "binary_little_endian.h"

namespace crypto {

	BinaryLittleEndian::~BinaryLittleEndian() {}

	bytes BinaryLittleEndian::Encode(const bytes& data) {
		return Encode((const unsigned char *)data.c_str(), data.size());
	}

	bytes BinaryLittleEndian::Encode(const unsigned char *data, size_t length) {
		return EndianMachine::isLittleEndian() ? bytes((const char *)data, length) : EndianMachine::filpBytes(data, length);
	}

	bytes BinaryLittleEndian::Decode(const bytes& data) {
		return EndianMachine::isLittleEndian() ? data : EndianMachine::filpBytes((const unsigned char *)data.c_str(), data.size());
	}
}
