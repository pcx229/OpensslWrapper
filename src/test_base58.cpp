

#include <iostream>
using namespace std;

#include "base58.h"
using namespace crypto;

void test_base58() {
    string str = "Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms, when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper. He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch, too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself. \"Teh monks were not to blame, in any case,\" he reflceted, on the steps. \"And if they're decent people here (and the Father Superior, I understand, is a nobleman) why not be friendly and courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness, and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have merely been takken in over this affair, just as they have.\"";
    string str_base58 = "5i1UeGbX63TamaNARDwzrb7WfujyEXGKyQ86aRn4kCPnCBbXW9MHqAXESAuMhbkq3ZDmKUKuPm7NaB3jGG6ZyuBttjkYoUXeCEkjWPeJSF3fkq5SvkbSMwu4LbLHGAruAtfQGR6zabr3PEvVJTjsLL2WZk7hevkV5LPo6YHzt9fQfaAcneoMRSppVvdAUvMFEK2qhvWcsrkqSeKPyRAath3dwTJ5xkbkwcgd4pf2kuphWBQJfPMuEBVLdVfnrQwPemtw5XF2LezWDLmzixZSpNcK7DtY9Xu4TYmmoiEgxkKCCs7Q1cg98EHeHciYZ8mkoHzCR9h49EuFhm32k9hqEUKzUXsWnTN323Y7zKCGz2V9Zb6qJ8rTonknfE7LeBcoA1YQLMpYJKVKzQKQwxLJizEeGBUMjbwkRr34ZzEUqNyKVPrcjCuvKzBPvJCMLPtqbBpocXDxgUiaM8AjyRJMVc1Mq2XPZpH7H3HHFeZYGyv5tqhWCJt7JnquHYnDHCrAWU8b5oeieY5zdr1gqDXhvd8iveA795WY7cpHWd14U4fA9BpFjYoowdVmXx2sooNmgRPDg8ESZLZBHxt7Z7BvGfC3hY5vxywzPixuu3ZsSJxhezUU2DQiYY7WRnGyUa2imrVosk3j5v31A5EgNsyxCr1wThqSbqs2tysyZbUnwzNntoCGdBxFX6Bknrkh2XYaFTDhzKqkAtJhwjB9gZLigsTPGSECS17PSJN3p4qMYVJHrfLm6ASv3N9iVf2ZVm9R7F278WVJ6BszmsLuCoZAD8hnL7NzKJjQG3eJsGF4q2FcuCeULHkxTrK9sDUd6R4CqCKfbxJo6uLEorM94A3r6GD7qwSQ31j1EnxMipi8R7WvcVkFjQ2jBYzbHLdna5Vawrk7Pq9XTvaZB7j5VNQTYgYyfqb3E7r1j3Cv3DJcNoGDpc5by7xf8sCR62JsMqDCWeiCrpWCdPgJK2hbJ2hsMJGiUWgUBj5zh9sm3dpQZQ8JDaYwmzpJtZ4niuUDcVZtsg751r1TXQmikrDaFPizXbGGPzwn96CHhmqoqytrGzGkLc1";
    string encoded = Base58::Encode((unsigned char *)str.c_str(), str.size());
    string decoded = Base58::Decode(str_base58);
    cout << "- string: " << str << endl;
    cout << "- encoded: " << encoded << endl;
    cout << "- should be: " << str_base58 << endl;
    cout << "- are equals? " << ((encoded == str_base58) ? "yes" : "no") << endl;
    cout << "- decoded: " << decoded << endl;
    cout << "- are equals? " << ((decoded == str) ? "yes" : "no") << endl;
}
