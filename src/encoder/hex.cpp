
#include "hex.h"

namespace crypto {

	Hex::~Hex() {}

	bytes Hex::Encode(const bytes& data) {
		return Encode((const unsigned char *)data.c_str(), data.size());
	}

	bytes Hex::Encode(const unsigned char *data, size_t length) {
		// build
		bytesstream ss;
		for (unsigned int i = 0; i < length; i++)
		{
			ss << std::hex << setw(2) << setfill('0') << (int)data[i];
		}
		return ss.str();
	}

	bytes Hex::Decode(const string& data) {
		static const char charset2value[] = {
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 17, 17, 17, 17, 17, 17,
			17, 10, 11, 12, 13, 14, 15, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 10, 11, 12, 13, 14, 15, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17,
			17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17, 17
		};
		// validate that string is hex
		if(data.size() % 2 != 0) {
			throw invalid_argument("size indicate that this is not a hex string");
		}
		// build
		bytesstream ss;
		for (unsigned int i = 0; i < data.size(); i+=2) {
			ss << (char)(charset2value[(unsigned int)data[i]] * 16 + charset2value[(unsigned int)data[i+1]]);
		}
		return ss.str();
	}

}
