
#ifndef _DATA_ENCODING_H_
#define _DATA_ENCODING_H_

#include <iostream>
#include <map>
using namespace std;

#include "encoder.h"
#include "base58.h"
#include "base64.h"
#include "hex.h"
#include "binary_big_endian.h"
#include "binary_little_endian.h"
#include "endian_machine.h"

namespace crypto {

    enum encoders_name{ BINARY, BINARY_LITTLE_ENDIAN, BINARY_BIG_ENDIAN, HEX, BASE64, BASE58 };

	class EncoderFactory final {

		private:

    		/**
    		 * initialize and register all build in encoders
    		 */
			EncoderFactory();

			EncoderFactory(const EncoderFactory &) = delete;
			EncoderFactory &operator=(const EncoderFactory &) = delete;

			map<encoders_name, Encoder*> map_encoders;

		public:
			~EncoderFactory();

			/**
			 * @return an encoders factory object instance
			 */
			static EncoderFactory *getInstance();

			/**
			 * get an encoder
			 * @param name an encoder name
			 * @return the encoder that correspond with the name given
			 */
			Encoder *by_name(encoders_name name);

			/**
			 * assign a name to an encoder object
			 * @param name an encoder name
			 * @param encoder an object to assign for that name
			 */
			void Register(encoders_name name, Encoder *encoder);
	};


    /**
     * convert raw data bytes to an encoded form
     */
	inline bytes encoding(const bytes &str, encoders_name output=BINARY) {
		return dynamic_cast<BlockEncoder*>(EncoderFactory::getInstance()->by_name(output))->Encode(str);
	}
	inline bytes encoding(const unsigned char *data, size_t length, encoders_name output=BINARY) {
		return dynamic_cast<BlockEncoder*>(EncoderFactory::getInstance()->by_name(output))->Encode(data, length);
	}

    /**
     * convert encoded form data back to raw bytes
     */
	inline bytes decoding(const bytes &str, encoders_name input=BINARY) {
		return dynamic_cast<BlockEncoder*>(EncoderFactory::getInstance()->by_name(input))->Decode(str);
	}
	inline bytes decoding(const unsigned char *data, size_t length, encoders_name input=BINARY) {
		return dynamic_cast<BlockEncoder*>(EncoderFactory::getInstance()->by_name(input))->Decode(bytes((char *)data, length));
	}

    /**
     * change format from one encoding to another
     */
	inline bytes transfer(const unsigned char *data, size_t length, encoders_name input, encoders_name output) {
		return encoding(decoding(data, length, input), output);
	}
	inline bytes transfer(const bytes &str, encoders_name input, encoders_name output) {
		return encoding(decoding(str, input), output);
	}
}

#endif
