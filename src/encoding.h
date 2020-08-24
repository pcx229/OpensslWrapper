
#ifndef _DATA_ENCODING_H_
#define _DATA_ENCODING_H_

#include <iostream>
using namespace std;

#include "base64.h"
#include "hex.h"

namespace crypto {

    enum data_encoding{ BINARY, HEX, BASE64 };

    /**
     * convert a raw bytes array to string object with the encoding specified
     * @param bytes an array of raw bytes to convert
     * @param length bytes array length
     * @param type encoding type HEX, BASE64 or BINARY(default)
     * @returns a string object that is the bytes given with the encoding
     */
    string encoding(const unsigned char *bytes, unsigned int length, data_encoding type=BINARY);

    /**
     * convert a string object with the encoding specified to raw bytes array
     * @param bytes an array of raw bytes to convert
     * @param length bytes array length
     * @param type encoding type HEX, BASE64 or BINARY(default)
     * @returns a string object that is the bytes given with the encoding
     */
    string decoding(const string &enc, data_encoding enc_type=BINARY);
}

#endif