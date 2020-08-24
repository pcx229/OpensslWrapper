

#include <iostream>
using namespace std;

#include "base64.h"

void test_base64() {
    string str = "Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms, when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper. He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch, too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself. \"Teh monks were not to blame, in any case,\" he reflceted, on the steps. \"And if they're decent people here (and the Father Superior, I understand, is a nobleman) why not be friendly and courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness, and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have merely been takken in over this affair, just as they have.\"";
    string str_base64 = "TWl1c292LCBhcyBhIG1hbiBtYW4gb2YgYnJlZWRpbmcgYW5kIGRlaWxjYWN5LCBjb3VsZCBub3QgYnV0IGZlZWwgc29tZSBpbndyZCBxdWFsbXMsIHdoZW4gaGUgcmVhY2hlZCB0aGUgRmF0aGVyIFN1cGVyaW9yJ3Mgd2l0aCBJdmFuOiBoZSBmZWx0IGFzaGFtZWQgb2YgaGF2aW4gbG9zdCBoaXMgdGVtcGVyLiBIZSBmZWx0IHRoYXQgaGUgb3VnaHQgdG8gaGF2ZSBkaXNkYWltZWQgdGhhdCBkZXNwaWNhYmxlIHdyZXRjaCwgRnlvZG9yIFBhdmxvdml0Y2gsIHRvbyBtdWNoIHRvIGhhdmUgYmVlbiB1cHNldCBieSBoaW0gaW4gRmF0aGVyIFpvc3NpbWEncyBjZWxsLCBhbmQgc28gdG8gaGF2ZSBmb3Jnb3R0ZW4gaGltc2VsZi4gIlRlaCBtb25rcyB3ZXJlIG5vdCB0byBibGFtZSwgaW4gYW55IGNhc2UsIiBoZSByZWZsY2V0ZWQsIG9uIHRoZSBzdGVwcy4gIkFuZCBpZiB0aGV5J3JlIGRlY2VudCBwZW9wbGUgaGVyZSAoYW5kIHRoZSBGYXRoZXIgU3VwZXJpb3IsIEkgdW5kZXJzdGFuZCwgaXMgYSBub2JsZW1hbikgd2h5IG5vdCBiZSBmcmllbmRseSBhbmQgY291cnRlb3VzIHdpdGh0aGVtPyBJIHdvbid0IGFyZ3VlLCBJJ2xsIGZhbGwgaW4gd2l0aCBldmVyeXRoaW5nLCBJJ2xsIHdpbiB0aGVtIGJ5IHBvbGl0bmVzcywgYW5kIHNob3cgdGhlbSB0aGF0IEkndmUgbm90aGluZyB0byBkbyB3aXRoIHRoYXQgQWVzb3AsIHRodGEgYnVmZm9vbiwgdGhhdCBQaWVycm90LCBhbmQgaGF2ZSBtZXJlbHkgYmVlbiB0YWtrZW4gaW4gb3ZlciB0aGlzIGFmZmFpciwganVzdCBhcyB0aGV5IGhhdmUuIg==";
    string encoded = Base64::Encode((unsigned char *)str.c_str(), str.size());
    string decoded = Base64::Decode(str_base64);
    cout << "- string: " << str << endl;
    cout << "- encoded: " << encoded << endl;
    cout << "- sould be: " << str_base64 << endl;
    cout << "- are equals? " << ((encoded == str_base64) ? "yes" : "no") << endl;
    cout << "- decoded: " << decoded << endl;
    cout << "- are equals? " << ((decoded == str) ? "yes" : "no") << endl;
}