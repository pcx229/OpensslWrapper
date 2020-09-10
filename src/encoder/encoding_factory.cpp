
#include "encoding_factory.h"

namespace crypto {

	EncoderFactory::EncoderFactory() {
		Register(BASE58, new Base58());
		Register(BASE64, new Base64());
		Register(HEX, new Hex());
		if(EndianMachine::isLittleEndian()) {
			Register(BINARY, new BinaryLittleEndian());
		} else {
			Register(BINARY, new BinaryBigEndian());
		}
		Register(BINARY_LITTLE_ENDIAN, new BinaryLittleEndian());
		Register(BINARY_BIG_ENDIAN, new BinaryBigEndian());
	}

	EncoderFactory::~EncoderFactory() {
		map<encoders_name, Encoder*>::iterator it = map_encoders.begin(), end = map_encoders.end();
		while(it != end) {
			delete it->second;
			it++;
		}
		map_encoders.clear();
	}

	EncoderFactory *EncoderFactory::getInstance() {
		static EncoderFactory instance;
		return &instance;
	}

	Encoder *EncoderFactory::by_name(encoders_name name) {
		map<encoders_name, Encoder*>::iterator it = map_encoders.find(name), end = map_encoders.end();
		if(it != end) {
			return it->second;
		}
		throw invalid_argument("unknown encoder name");
	}

	void EncoderFactory::Register(encoders_name name, Encoder *encoder) {
		map_encoders[name] = encoder;
	}

    
}
