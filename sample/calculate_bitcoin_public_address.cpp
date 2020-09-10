
#include <iostream>
using namespace std;

#include "ec.h"
#include "hash.h"
using namespace crypto;

int main() {
	EC e;
	string checksum, address;
	string stage0, stage1, stage2, stage3, stage4, stage5, stage6, stage7, stage8, stage9;

	cout << "Calculating Bitcoin Public Address" << endl;

	// 0 - a private ECDSA key
	stage0 = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725";
	cout << "0) private key: " << stage0 << endl;
	// 1 - the corresponding public key
	e.load_private_by_number(stage0, secp256k1, HEX);
	stage1 = e.get_public_point(EC::public_key_point_format::COMPRESSED, HEX);
	//pub = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
	cout << "1) public key: " << stage1 << endl;
	// 2 - sha256 hash on public key
	stage2 = Hash<sha256>(stage1, HEX);
	cout << "2) sha256 on public: " << stage2 << endl;
	// 3 - ripemd160 hash on last stage result
	stage3 = Hash<ripemd160>(stage2, HEX);
	cout << "3) ripemd160 on previous result: " << stage3 << endl;
	// 4 - add 0x00 byte at the beginning of previous stage result
	//     this is a version byte for main network address
	stage4 = (stage3).insert(0, "00");
	cout << "4) add version byte 0x00 to previous result: " << stage4 << endl;
	// 5 - sha256 hash on last stage result
	stage5 = Hash<sha256>(stage4, HEX);
	cout << "5) sha256 on previous result: " << stage5 << endl;
	// 6 - sha256 hash on last stage result
	stage6 = Hash<sha256>(stage5, HEX);
	cout << "6) sha256 on previous result: " << stage6 << endl;
	// 7 - the checksum is 4 bytes from the beginning of last stage result
	stage7.insert(0, stage6, 0, 8);
	cout << "7) checksum is: " << stage7 << endl;
	// 8 - add checksum to the end of stage 4 result
	stage8 = stage4.append(stage7);
	cout << "8) add checksum to the end of the extended ripemd160 result(4): " << stage8 << endl;
	// 9 - do base58 encoding on the last stage result
	stage9 = transfer(stage8, HEX, BASE58);
	cout << "9) base58 encoding on previous result: " << stage9 << endl;

	// extract wanted parameters
	address = stage9;
	checksum = stage7;

	// results
	cout << "address: " << address << endl;
	cout << "checksum: " << checksum << endl;

	return 0;
}
