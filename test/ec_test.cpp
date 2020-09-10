
#include <cstdio>
#include <fstream>
#include <iostream>
using namespace std;

#include "ec.h"
using namespace crypto;

#include <gtest/gtest.h>

namespace {

TEST(EC, Loading) {
	EC enc;

	ASSERT_NO_THROW(enc.load_private("./test/private.pem"));
	ASSERT_TRUE(enc.get_private_ANS1(BASE64) == "MHQCAQEEINwMDn5y//ibdTn7q1GNvEpbdlquEuPzqIYxO10qKM04oAcGBSuBBAAKoUQDQgAEwFjK8PZojN5GFkqIG7T0NCCDoTaByQhssBL+5ujiqm109bNR9kO+Nc4znvysNyJNQV8gvWdcc8kuthZF7vHWpg==");
	ASSERT_TRUE(enc.get_public_ANS1(BASE64) == "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEwFjK8PZojN5GFkqIG7T0NCCDoTaByQhssBL+5ujiqm109bNR9kO+Nc4znvysNyJNQV8gvWdcc8kuthZF7vHWpg==");
}

TEST(EC, Saving) {
	EC a, b;

	a.load_private("./test/private.pem");
	a.save("./test/test_save_private", DER, "./test/test_save_public", DER);

	b.load_private("./test/test_save_private");

	ASSERT_TRUE(a.get_private_ANS1(HEX) == b.get_private_ANS1(HEX));
	ASSERT_TRUE(a.get_public_ANS1(HEX) == b.get_public_ANS1(HEX));

	remove("./test/test_save_private");
	remove("./test/test_save_public");
}

TEST(EC, EncryptionPrivateKey) {
	EC a, b;

	a.load_private("./test/private.pem");
	a.save_private("./test/test_enc_private.pem", PEM, des_cfb1, "hello world");

	b.load_private("./test/test_enc_private.pem", PEM, "hello world");

	ASSERT_TRUE(a.get_private_ANS1(HEX) == b.get_private_ANS1(HEX));

	remove("./test/test_enc_private.pem");
}

TEST(EC, GenerateKeys) {
	EC a;
	string prv, pub;

	a.generate_keys(secp256k1);

	pub = a.get_public_ANS1(HEX);
	prv = a.get_private_ANS1(HEX);

	ASSERT_EQ(prv.size(), 236);
	ASSERT_EQ(pub.size(), 176);

	ASSERT_NO_THROW(a.load_private_by_ANS1(prv, HEX));
	ASSERT_NO_THROW(a.load_public_by_ANS1(pub, HEX));
	ASSERT_THROW(a.get_private_ANS1(HEX), std::runtime_error);

	pub = a.get_public_ANS1(HEX);
	ASSERT_EQ(pub.size(), 176);
}

TEST(EC, Verify) {
	EC a;
	stringstream sig_gen;
	ifstream data("./test/data", ios::binary);
	ifstream sig("./test/sig", ios::binary);

	a.load_private("./test/private.pem");
	ASSERT_TRUE(a.verify(sha1, data, sig));

	data.close();
	sig.close();
}

TEST(EC, Sign) {
	EC a;
	stringstream sig_gen;
	ifstream data("./test/data", ios::binary);

	a.load_private("./test/private.pem");
	a.sign(sha1, data, sig_gen);
	data.clear();
	data.seekg(0, ios::beg);
	ASSERT_TRUE(a.verify(sha1, data, sig_gen));

	data.close();
}

}
