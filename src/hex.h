
#ifndef _HEX_H_
#define _HEX_H_

#include <sstream>
#include <iomanip>
#include <iostream>
using namespace std;

class Hex {
 public:

    /**
     * encode a raw data to a hex string
     * @param data an array of charectors to encode
     * @param length size of the data array
     * @returns a hex string representing the data
     */
    static string Encode(const unsigned char *data, size_t length);

    /**
     * decode a hex string to the original raw data
     * @param data a hex string
     * @returns the original raw data the this hex string representing
     * @throw invalid_argument exception if the data is not a valid hex string
     */
    static string Decode(const string& data);
};

#endif /* _HEX_H_ */