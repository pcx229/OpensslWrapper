

#include <sstream>
#include <iostream>
using namespace std;

#include "ec.h"
#include "encoder/base64.h"
using namespace crypto;

int main()
{
    EC e;
    string pkey;
    Base64 encoder;

    try {

		// generate keys

		cout << endl << "- Generating keys:" << endl;

		e.generate_keys(secp256k1);
		cout << "private key:\t" << e.get_private_ANS1() << endl;
		cout << "public key:\t" << e.get_public_ANS1() << endl;

		// save with a key

		cout << endl << "- Saving keys to files private.pem and public.pem" << endl;

		e.save_private("private.pem", AUTO, des_ede_cbc, "hello");
		e.save_public("public.pem");

		// load key files

		cout << endl << "- Loading keys from files private.pem" << endl;

		e.load_private("private.pem", AUTO, "hello");

		// sign and verify data

		stringstream sdata;
		sdata << "hello world";

		// sign

		cout << endl << "- Signing data with private key:" << endl;

		stringstream signature;
		e.sign(sha1, sdata, signature);
		cout << "data: '" + sdata.str() + "' , signature: " << encoder.Encode((const unsigned char *)signature.str().c_str(), signature.str().size()) << endl;

		// verify

		cout << endl << "- Verifying data with public key:" << endl;

		sdata.clear();
		sdata.seekg(0, ios::beg);
		cout << "is signature valid? " << (e.verify(sha1, sdata, signature) ? "yes" : "no") << endl;

		// setting public key by a point representation

		cout << endl << "- public key as a point" << endl;
		e.generate_keys(secp256k1);
		cout << "original public key: " << e.get_public_ANS1() << endl;
		pkey = e.get_public_point(EC::public_key_point_format::COMPRESSED, HEX);
		cout << "public key as compressed string: " << pkey << endl;
		e.clear();
		cout << "keys are cleared and setting public key by point" << endl;
		e.load_public_by_point(pkey, secp256k1 ,HEX);
		cout << "recovered public key: " << e.get_public_ANS1() << endl;

		// generating public key by a private key

		cout << endl << "- public key by a private key" << endl;
		e.generate_keys(secp256k1);
		cout << "original public key: " << e.get_private_ANS1() << endl;
		pkey = e.get_private_ANS1();
		e.clear();
		cout << "keys are cleared and loading private key" << endl;
		e.load_private_by_ANS1(pkey);
		cout << "recovered public key: " << e.get_private_ANS1() << endl;

    } catch(const exception &e) {
    	cerr << e.what();
    }

    return 0;
}
