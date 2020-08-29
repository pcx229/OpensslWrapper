

#include <iostream>
using namespace std;

#include "base64.h"
using namespace crypto;

int main() {
    string str = "There's no place like home.";

    cout << "original string: " << str << endl;

    // encoding

    string encoded = Base64::Encode((unsigned char *)str.c_str(), str.size());

    cout << "encoded with base64: " << encoded << endl;

    // decoding

    string decoded = Base64::Decode(encoded);
    cout << "back to original: " << decoded << endl;

    return 0;
}
