

#include <iostream>
using namespace std;

#include "encoder/base58.h"
using namespace crypto;

int main() {
	Base58 encoder;
    string str = "There's no place like home.";

    cout << "original string: " << str << endl;

    // encoding

    string encoded = encoder.Encode((unsigned char *)str.c_str(), str.size());

    cout << "encoded with base64: " << encoded << endl;

    // decoding

    string decoded = encoder.Decode(encoded);
    cout << "back to original: " << decoded << endl;

    return 0;
}
