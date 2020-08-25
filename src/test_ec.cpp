

#include <sstream>
#include <iostream>
using namespace std;

#include "ec.h"
using namespace crypto;

void test_ec()
{
    EC e;

    try {

		// Generate keys

		cout << "- Generating keys:" << endl;

		e.generate_keys(secp256k1);
		cout << "private key:\t" << e.get_private() << endl;
		cout << "public key:\t" << e.get_public() << endl;

		// Save with a key

		cout << "- Saving keys to files private.pem and public.pem" << endl;

		e.save_private("private.pem", AUTO, des_ede_cbc, "hello");
		e.save_public("public.pem");

		// Load key files

		cout << "- Loading keys from files private.pem and public.pem" << endl;

		e.load_private("private.pem", AUTO, "hello");
		e.load_public("public.pem");

		// Sign and verify data

		stringstream sdata;
		sdata << "hello world";

		// Sign

		cout << "- Signing data with private key:" << endl;

		stringstream signature;
		e.sign(sha1, sdata, signature);
		cout << "data: '" + sdata.str() + "' , signature: " << Base64::Encode((const unsigned char *)signature.str().c_str(), signature.str().size()) << endl;

		// Verify

		cout << "- Verifying data with public key:" << endl;

		sdata.clear();
		sdata.seekg(0, ios::beg);
		cout << "is signature valid? " << (e.verify(sha1, sdata, signature) ? "yes" : "no") << endl;

    } catch(const exception &e) {
    	cerr << e.what();
    }
}
