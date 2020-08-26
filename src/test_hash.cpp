

#include <sstream>
#include <iostream>
using namespace std;

#include "hash.h"
using namespace crypto;

void test_hash()
{
    // string

	cout << "- String hashing:" << endl << endl;

	string str = "hello world";
	cout << "string: " << str << endl;
	cout << "md4=" << "\t" << Hash<md4>(str) << endl;
	cout << "md5=" << "\t" << Hash<md5>(str) << endl;
	cout << "md5_sha1=" << "\t" << Hash<md5_sha1>(str) << endl;
	cout << "blake2b512=" << "\t" << Hash<blake2b512>(str) << endl;
	cout << "blake2s256=" << "\t" << Hash<blake2s256>(str) << endl;
	cout << "sha1=" << "\t" << Hash<sha1>(str) << endl;
	cout << "sha224=" << "\t" << Hash<sha224>(str) << endl;
	cout << "sha256=" << "\t" << Hash<sha256>(str) << endl;
	cout << "sha384=" << "\t" << Hash<sha384>(str) << endl;
	cout << "sha512=" << "\t" << Hash<sha512>(str) << endl;
	cout << "sha512_224=" << "\t" << Hash<sha512_224>(str) << endl;
	cout << "sha512_256=" << "\t" << Hash<sha512_256>(str) << endl;
	cout << "sha3_224=" << "\t" << Hash<sha3_224>(str) << endl;
	cout << "sha3_256=" << "\t" << Hash<sha3_256>(str) << endl;
	cout << "sha3_384=" << "\t" << Hash<sha3_384>(str) << endl;
	cout << "sha3_512=" << "\t" << Hash<sha3_512>(str) << endl;
	cout << "shake128=" << "\t" << Hash<shake128>(str) << endl;
	cout << "shake256=" << "\t" << Hash<shake256>(str) << endl;
	cout << "mdc2=" << "\t" << Hash<mdc2>(str) << endl;
	cout << "ripemd160=" << "\t" << Hash<ripemd160>(str) << endl;
	cout << "whirlpool=" << "\t" << Hash<whirlpool>(str) << endl;
	cout << "sm3=" << "\t" << Hash<sm3>(str) << endl;

	// stream

	cout << endl << "- Stream hashing:" << endl << endl;

	stringstream ss;
    ss << "hello" << " " << "world" << " " << "this" << " " << "is" << " " << "a" << " " << "test";
    cout << "sha1(hello world this is a test)=\t" << Hash<sha1>(ss.str()) << endl;
    cout << "sha1[stream >> hello world this is a test]=\t" << Hash<sha1>(ss) << endl;

    // copy state

	cout << endl << "- Copying state:" << endl << endl;

    Hash<sha1> h1, h2;
    h1 << "hello" << " " << "world";
    h2 = h1;
    cout << "sha1(hello world)=\t" << h1 << endl;
    h2 << " " << "and" << " " << "goodbye!";
    cout << "sha1(hello world and goodbye!)=\t" << h2 << endl;
    cout << "sha1(hello world and goodbye!) bytes=\t" << h2.digest(BINARY) << endl;

    // string assignment

	cout << endl << "- String assignment:" << endl << endl;

    string hex_hash_hello_world = Hash<sha256>("hello world");
    cout << "hash of 'hello world': " << hex_hash_hello_world << endl;
}
