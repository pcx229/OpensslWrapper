

#include <iostream>
using namespace std;

#include "base58.h"
#include "encoding.h"
using namespace crypto;

#include <gtest/gtest.h>

namespace {

TEST(Base58, ShortString) {
	string str_short = "Mi";
	string str_short_base58 = "6tg";
	string encoded = Base58::Encode((unsigned char *) str_short.c_str(), str_short.size());
	string decoded = Base58::Decode(str_short_base58);
	EXPECT_STREQ(encoded.c_str(), str_short_base58.c_str());
	EXPECT_STREQ(decoded.c_str(), str_short.c_str());
}

TEST(Base58, LongString) {
	string str_long = "Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms, when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper. He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch, too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself. \"Teh monks were not to blame, in any case,\" he reflceted, on the steps. \"And if they're decent people here (and the Father Superior, I understand, is a nobleman) why not be friendly and courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness, and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have merely been takken in over this affair, just as they have.\"";
	string str_long_base58 = "5i1UeGbX63TamaNARDwzrb7WfujyEXGKyQ86aRn4kCPnCBbXW9MHqAXESAuMhbkq3ZDmKUKuPm7NaB3jGG6ZyuBttjkYoUXeCEkjWPeJSF3fkq5SvkbSMwu4LbLHGAruAtfQGR6zabr3PEvVJTjsLL2WZk7hevkV5LPo6YHzt9fQfaAcneoMRSppVvdAUvMFEK2qhvWcsrkqSeKPyRAath3dwTJ5xkbkwcgd4pf2kuphWBQJfPMuEBVLdVfnrQwPemtw5XF2LezWDLmzixZSpNcK7DtY9Xu4TYmmoiEgxkKCCs7Q1cg98EHeHciYZ8mkoHzCR9h49EuFhm32k9hqEUKzUXsWnTN323Y7zKCGz2V9Zb6qJ8rTonknfE7LeBcoA1YQLMpYJKVKzQKQwxLJizEeGBUMjbwkRr34ZzEUqNyKVPrcjCuvKzBPvJCMLPtqbBpocXDxgUiaM8AjyRJMVc1Mq2XPZpH7H3HHFeZYGyv5tqhWCJt7JnquHYnDHCrAWU8b5oeieY5zdr1gqDXhvd8iveA795WY7cpHWd14U4fA9BpFjYoowdVmXx2sooNmgRPDg8ESZLZBHxt7Z7BvGfC3hY5vxywzPixuu3ZsSJxhezUU2DQiYY7WRnGyUa2imrVosk3j5v31A5EgNsyxCr1wThqSbqs2tysyZbUnwzNntoCGdBxFX6Bknrkh2XYaFTDhzKqkAtJhwjB9gZLigsTPGSECS17PSJN3p4qMYVJHrfLm6ASv3N9iVf2ZVm9R7F278WVJ6BszmsLuCoZAD8hnL7NzKJjQG3eJsGF4q2FcuCeULHkxTrK9sDUd6R4CqCKfbxJo6uLEorM94A3r6GD7qwSQ31j1EnxMipi8R7WvcVkFjQ2jBYzbHLdna5Vawrk7Pq9XTvaZB7j5VNQTYgYyfqb3E7r1j3Cv3DJcNoGDpc5by7xf8sCR62JsMqDCWeiCrpWCdPgJK2hbJ2hsMJGiUWgUBj5zh9sm3dpQZQ8JDaYwmzpJtZ4niuUDcVZtsg751r1TXQmikrDaFPizXbGGPzwn96CHhmqoqytrGzGkLc1";
	string encoded = Base58::Encode((unsigned char *) str_long.c_str(), str_long.size());
	string decoded = Base58::Decode(str_long_base58);
	EXPECT_STREQ(encoded.c_str(), str_long_base58.c_str());
	EXPECT_STREQ(decoded.c_str(), str_long.c_str());
}

TEST(Base58, ZeroLeading) {
	string hex_zeros = "00000879ab323000";
	string hex_zeros_base58 = "115DnYk7Qj";
	string str = decoding(hex_zeros, HEX);
	string encoded = Base58::Encode((unsigned char *) str.c_str(), str.size());
	string decoded = Base58::Decode(hex_zeros_base58);
	string hex_decoded = encoding(decoded, HEX);
	EXPECT_STREQ(encoded.c_str(), hex_zeros_base58.c_str());
	EXPECT_STREQ(hex_decoded.c_str(), hex_zeros.c_str());
}

TEST(Base58, Empty) {
	string empty;
	string encoded = Base58::Encode((unsigned char *) empty.c_str(), empty.size());
	string decoded = Base58::Decode(empty);
	EXPECT_STREQ(encoded.c_str(), empty.c_str());
	EXPECT_STREQ(decoded.c_str(), empty.c_str());
}

}

