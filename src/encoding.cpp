
#include "encoding.h"

namespace crypto {

	string encoding(const unsigned char *bytes, unsigned int length, data_encoding type) {
        switch (type)
        {
            case HEX:
                return Hex::Encode(bytes, length);
            case BINARY:
                return string((const char *)bytes, length);
            case BASE64:
                return Base64::Encode(bytes, length);
        }
        throw invalid_argument("unknown data encoding type");
    }

    string decoding(const string &enc, data_encoding enc_type) {
        switch (enc_type)
        {
            case HEX:
                return Hex::Decode(enc);
            case BINARY:
                return enc;
            case BASE64:
                return Base64::Decode(enc);
        }
        throw invalid_argument("unknown data encoding type");
    }
    
}
