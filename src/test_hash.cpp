

#include <sstream>
#include <iostream>
using namespace std;

#include "hash.h"
using namespace crypto;

template<hash_types type> using chash = crypto::hash<type>;

void test_hash()
{
    // string

	cout << "string hashing:" << endl << endl;

	string str = "hello world";
	cout << "string: " << str << endl;
	cout << "md4=" << "\t" << chash<md4>(str) << endl;
	cout << "md5=" << "\t" << chash<md5>(str) << endl;
	cout << "md5_sha1=" << "\t" << chash<md5_sha1>(str) << endl;
	cout << "blake2b512=" << "\t" << chash<blake2b512>(str) << endl;
	cout << "blake2s256=" << "\t" << chash<blake2s256>(str) << endl;
	cout << "sha1=" << "\t" << chash<sha1>(str) << endl;
	cout << "sha224=" << "\t" << chash<sha224>(str) << endl;
	cout << "sha256=" << "\t" << chash<sha256>(str) << endl;
	cout << "sha384=" << "\t" << chash<sha384>(str) << endl;
	cout << "sha512=" << "\t" << chash<sha512>(str) << endl;
	cout << "sha512_224=" << "\t" << chash<sha512_224>(str) << endl;
	cout << "sha512_256=" << "\t" << chash<sha512_256>(str) << endl;
	cout << "sha3_224=" << "\t" << chash<sha3_224>(str) << endl;
	cout << "sha3_256=" << "\t" << chash<sha3_256>(str) << endl;
	cout << "sha3_384=" << "\t" << chash<sha3_384>(str) << endl;
	cout << "sha3_512=" << "\t" << chash<sha3_512>(str) << endl;
	cout << "shake128=" << "\t" << chash<shake128>(str) << endl;
	cout << "shake256=" << "\t" << chash<shake256>(str) << endl;
	cout << "mdc2=" << "\t" << chash<mdc2>(str) << endl;
	cout << "ripemd160=" << "\t" << chash<ripemd160>(str) << endl;
	cout << "whirlpool=" << "\t" << chash<whirlpool>(str) << endl;
	cout << "sm3=" << "\t" << chash<sm3>(str) << endl;

	// stream

	cout << endl << "stream hashing:" << endl << endl;

	stringstream ss;
    ss << "hello" << " " << "world" << " " << "this" << " " << "is" << " " << "a" << " " << "test";
    cout << "sha1(hello world this is a test)=\t" << chash<sha1>(ss.str()) << endl;
    cout << "sha1[stream >> hello world this is a test]=\t" << chash<sha1>(ss) << endl;

    // copy state

	cout << endl << "copying state:" << endl << endl;

    chash<sha1> h1, h2;
    h1 << "hello" << " " << "world";
    h2 = h1;
    cout << "sha1(hello world)=\t" << h1 << endl;
    h2 << " " << "and" << " " << "goodbye!";
    cout << "sha1(hello world and goodbye!)=\t" << h2 << endl;
    cout << "sha1(hello world and goodbye!) bytes=\t" << h2.digest(BINARY) << endl;

    // string assignment

	cout << endl << "string assignment:" << endl << endl;

    string hex_hash_hello_world = chash<sha256>("hello world");
    cout << "hash of 'hello world': " << hex_hash_hello_world << endl;
}
