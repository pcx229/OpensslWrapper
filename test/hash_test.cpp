

#include <sstream>
#include <iostream>
using namespace std;

#include "hash.h"
using namespace crypto;

#include <gtest/gtest.h>

namespace {

TEST(Hash, Algorithems) {

	string str = "hello world";

	ASSERT_TRUE(str == "hello world");
	ASSERT_TRUE(Hash<md4>(str) == "aa010fbc1d14c795d86ef98c95479d17");
	ASSERT_TRUE(Hash<md5>(str) == "5eb63bbbe01eeed093cb22bb8f5acdc3");
	ASSERT_TRUE(Hash<md5_sha1>(str) == "5EB63BBBE01EEED093CB22BB8F5ACDC32AAE6C35C94FCFB415DBE95F408B9CE91EE846ED");
	ASSERT_TRUE(Hash<blake2b512>(str) == "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0");
	ASSERT_TRUE(Hash<blake2s256>(str) == "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b");
	ASSERT_TRUE(Hash<sha1>(str) == "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed");
	ASSERT_TRUE(Hash<sha224>(str) == "2F05477FC24BB4FAEFD86517156DAFDECEC45B8AD3CF2522A563582B");
	ASSERT_TRUE(Hash<sha256>(str) == "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
	ASSERT_TRUE(Hash<sha384>(str) == "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd");
	ASSERT_TRUE(Hash<sha512>(str) == "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
	ASSERT_TRUE(Hash<sha512_224>(str) == "22E0D52336F64A998085078B05A6E37B26F8120F43BF4DB4C43A64EE");
	ASSERT_TRUE(Hash<sha512_256>(str) == "0AC561FAC838104E3F2E4AD107B4BEE3E938BF15F2B15F009CCCCD61A913F017");
	ASSERT_TRUE(Hash<sha3_224>(str) == "DFB7F18C77E928BB56FAEB2DA27291BD790BC1045CDE45F3210BB6C5");
	ASSERT_TRUE(Hash<sha3_256>(str) == "644BCC7E564373040999AAC89E7622F3CA71FBA1D972FD94A31C3BFBF24E3938");
	ASSERT_TRUE(Hash<sha3_384>(str) == "83BFF28DDE1B1BF5810071C6643C08E5B05BDB836EFFD70B403EA8EA0A634DC4997EB1053AA3593F590F9C63630DD90B");
	ASSERT_TRUE(Hash<sha3_512>(str) == "840006653E9AC9E95117A15C915CAAB81662918E925DE9E004F774FF82D7079A40D4D27B1B372657C61D46D470304C88C788B3A4527AD074D1DCCBEE5DBAA99A");
	ASSERT_TRUE(Hash<shake128>(str) == "3a9159f071e4dd1c8c4f968607c30942");
	ASSERT_TRUE(Hash<shake256>(str) == "369771bb2cb9d2b04c1d54cca487e372d9f187f73f7ba3f65b95c8ee7798c527");
	ASSERT_TRUE(Hash<mdc2>(str) == "9ce411cc3449bf73a54568d783b5900d");
	ASSERT_TRUE(Hash<ripemd160>(str) == "98c615784ccb5fe5936fbc0cbe9dfdb408d92f0f");
	ASSERT_TRUE(Hash<whirlpool>(str) == "8d8309ca6af848095bcabaf9a53b1b6ce7f594c1434fd6e5177e7e5c20e76cd30936d8606e7f36acbef8978fea008e6400a975d51abe6ba4923178c7cf90c802");
	ASSERT_TRUE(Hash<sm3>(str) == "44f0061e69fa6fdfc290c494654a05dc0c053da7e5c52b84ef93a9d67d3fff88");
}

TEST(Hash, Updates) {
	Hash<md5> h;
	h.update("Its Alive 1!");
	h << "Its Alive 2!" << "Its Alive 3!";
	stringstream ss;
	ss << "Its Alive 4!" << "Its Alive 5!";
	h << ss;
	ASSERT_TRUE(h == "f1546e5ca0bd1bfe1886cb177b5da829");
}

TEST(Hash, CopyState) {
	Hash<md5> h1, h2;
	h1 << "hello";
	h2 = h1;
	ASSERT_TRUE(h1 == "5d41402abc4b2a76b9719d911017c592");
	h2 << " world";
	ASSERT_TRUE(h2 == "5eb63bbbe01eeed093cb22bb8f5acdc3");
}

TEST(Hash, Output) {
	Hash<md5> h("hello world");
	ASSERT_TRUE(h == "5eb63bbbe01eeed093cb22bb8f5acdc3");
	ASSERT_TRUE(h.digest() == "5eb63bbbe01eeed093cb22bb8f5acdc3");
	ASSERT_TRUE(h.digest(HEX) == "5eb63bbbe01eeed093cb22bb8f5acdc3");
	unsigned char binary[] = { 0x5e, 0xb6, 0x3b, 0xbb, 0xe0, 0x1e, 0xee, 0xd0, 0x93, 0xcb, 0x22, 0xbb, 0x8f, 0x5a, 0xcd, 0xc3 };
	int size = 16;
	ASSERT_TRUE(h.digest(BINARY) == string((const char*)binary, size));
	ASSERT_TRUE(h.digest(BASE64) == "XrY7u+Ae7tCTyyK7j1rNww==");
}

}

