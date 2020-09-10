
#include <sstream>
#include <iostream>
using namespace std;

#include "encoder/big_num.h"
using namespace crypto;

#include <gtest/gtest.h>

namespace {

TEST(BigNum, Constructor) {

	// empty

	ASSERT_EQ(*BigNum(), 0);

	// number

	ASSERT_EQ(*BigNum(435), 435);

	// string decimal

	ASSERT_EQ(*BigNum("435436456"), 435436456);

	// string hex

	ASSERT_EQ(*BigNum("ff324a", BigNum::encoding::HEX), 16724554);

	// binary little endian

	unsigned int l = 42; // hex 00 00 00 2a
	ASSERT_EQ(*BigNum(reinterpret_cast<unsigned char *>(&l), sizeof(unsigned int), BigNum::encoding::BINARY_LITTLE_ENDIAN), 42);

	// binary big endian

	unsigned int b = 704643072; // hex 2a 00 00 00
	ASSERT_EQ(*BigNum(reinterpret_cast<unsigned char *>(&b), sizeof(unsigned int)), 42);

	// copy
	BigNum ca = 5;
	BigNum cb = ca;
	ASSERT_EQ(*ca, *cb);
}

TEST(BigNum, Comparison) {
	BigNum a = 6, b = 7;
	ASSERT_FALSE(a == b);
	ASSERT_TRUE(a != b);
	ASSERT_TRUE(a < b);
	ASSERT_FALSE(a > b);
	ASSERT_EQ(a.compare(b), -1);
}

TEST(BigNum, Arithmetic) {
	BigNum a = 6, b = 7;
	ASSERT_EQ(*(a+b), 13);
	ASSERT_EQ(*(a-b), -1);
	ASSERT_EQ(*(a*b), 42);
	ASSERT_EQ(*(a/b), 0);
	ASSERT_EQ(*(a%b), 6);
	ASSERT_EQ(*(a++), 7);
	ASSERT_EQ(*(b--), 6);
	b = a;
	ASSERT_EQ(*b, 7);
}

TEST(BigNum, Print) {
	BigNum a = 53243;
	stringstream ss;

	// decimal

	ss.str("");
	a.print(ss);
	ASSERT_STREQ(ss.str().c_str(), "53243");
	ss.str("");
	ss << a; // with operator
	ASSERT_STREQ(ss.str().c_str(), "53243");

	// hex

	ss.str("");
	a.print(ss, BigNum::encoding::HEX);
	ASSERT_STREQ(ss.str().c_str(), "CFFB");

	// little endian

	ss.str("");
	a.print(ss, BigNum::encoding::BINARY_LITTLE_ENDIAN);
	unsigned short se=0;
	ss.read(reinterpret_cast<char *>(&se), 2);
	ASSERT_EQ(se, 53243);

	// big endian

	ss.str("");
	a.print(ss, BigNum::encoding::BINARY_BIG_ENDIAN);
	unsigned short be=0;
	ss.read(reinterpret_cast<char *>(&be), 2);
	ASSERT_EQ(be, 64463);
}

}

