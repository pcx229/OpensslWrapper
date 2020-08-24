

#include <sstream>
#include <iostream>
using namespace std;

#include "ec.h"
using namespace crypto;

void test_ec()
{
    EC e;

    // generate keys

    cout << "- gemerating keys:" << endl;

    e.generate_keys(secp256k1);
    cout << "private key:\t" << e.get_private() << endl;
    cout << "public key:\t" << e.get_public() << endl;

    // save with a key

    cout << "- saving keys to files private.pem and public.pem" << endl;

    e.save_private("private.pem", AUTO, des_ede_cbc, "hello");
    e.save_public("public.pem");

    // load key files

    cout << "- loading keys from files private.pem and public.pem" << endl;
    
    e.load_private("private.pem", AUTO, "hello");
    e.load_public("public.pem");

    // sign and verify data

    stringstream sdata;
    sdata << "hello world";

    // sign 

    cout << "- signing data with private key:" << endl;

    stringstream signature;
    e.sign(sha1, sdata, signature);
    cout << "data: '" + sdata.str() + "' , signature: " << Base64::Encode((const unsigned char *)signature.str().c_str(), signature.str().size()) << endl;
    
    // verify

    cout << "- verifying data with public key:" << endl;
    
    sdata.clear();
    sdata.seekg(0, ios::beg);
    cout << "is signature valid? " << (e.verify(sha1, sdata, signature) ? "yes" : "no") << endl;

}