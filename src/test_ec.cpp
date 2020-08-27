

#include <sstream>
#include <iostream>
using namespace std;

#include "ec.h"
using namespace crypto;

void test_ec()
{
    EC e;
    string pkey;

    try {

		// generate keys

		cout << endl << "- Generating keys:" << endl;

		e.generate_keys(secp256k1);
		cout << "private key:\t" << e.get_private() << endl;
		cout << "public key:\t" << e.get_public() << endl;

		// save with a key

		cout << endl << "- Saving keys to files private.pem and public.pem" << endl;

		e.save_private("private.pem", AUTO, des_ede_cbc, "hello");
		e.save_public("public.pem");

		// load key files

		cout << endl << "- Loading keys from files private.pem and public.pem" << endl;

		e.load_private("private.pem", AUTO, "hello");
		e.load_public("public.pem");

		// sign and verify data

		stringstream sdata;
		sdata << endl << "hello world";

		// sign

		cout << endl << "- Signing data with private key:" << endl;

		stringstream signature;
		e.sign(sha1, sdata, signature);
		cout << "data: '" + sdata.str() + "' , signature: " << Base64::Encode((const unsigned char *)signature.str().c_str(), signature.str().size()) << endl;

		// verify

		cout << endl << "- Verifying data with public key:" << endl;

		sdata.clear();
		sdata.seekg(0, ios::beg);
		cout << "is signature valid? " << (e.verify(sha1, sdata, signature) ? "yes" : "no") << endl;

		// setting public key by a point representation

		cout << endl << "- public key as a point" << endl;
		e.generate_keys(secp256k1);
		cout << "original public key: " << e.get_public() << endl;
		pkey = e.get_public_point(EC::public_key_point_format::COMPRESSED, EC::public_key_point_encoding::HEX);
		cout << "public key as compressed string: " << pkey << endl;
		e.clear();
		cout << "keys are cleared and setting public key by point" << endl;
		e.set_public_by_point(pkey, secp256k1 ,EC::public_key_point_encoding::HEX);
		cout << "recovered public key: " << e.get_public() << endl;

		// generating public key by a private key

		cout << endl << "- public key by a private key" << endl;
		e.generate_keys(secp256k1);
		cout << "original public key: " << e.get_private() << endl;
		pkey = e.get_private();
		e.clear();
		cout << "keys are cleared and loading private key" << endl;
		e.load_private(pkey);
		cout << "generating public key" << endl;
		e.generate_public();
		cout << "original public key: " << e.get_private() << endl;

    } catch(const exception &e) {
    	cerr << e.what();
    }
}
