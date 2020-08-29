
#include <iostream>
using namespace std;

#include "hex.h"
using namespace crypto;

#include <gtest/gtest.h>

namespace {

TEST(Hex, ShortString) {
	string str_short = "Mi";
	string str_short_hex = "4d69";
	string encoded = Hex::Encode((unsigned char *) str_short.c_str(), str_short.size());
	string decoded = Hex::Decode(str_short_hex);
	EXPECT_STREQ(encoded.c_str(), str_short_hex.c_str());
	EXPECT_STREQ(decoded.c_str(), str_short.c_str());
}

TEST(Hex, LongString) {
	string str_long = "Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms, when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper. He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch, too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself. \"Teh monks were not to blame, in any case,\" he reflceted, on the steps. \"And if they're decent people here (and the Father Superior, I understand, is a nobleman) why not be friendly and courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness, and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have merely been takken in over this affair, just as they have.\"";
	string str_long_hex = "4d6975736f762c2061732061206d616e206d616e206f66206272656564696e6720616e64206465696c636163792c20636f756c64206e6f7420627574206665656c20736f6d6520696e777264207175616c6d732c207768656e20686520726561636865642074686520466174686572205375706572696f7227732077697468204976616e3a2068652066656c7420617368616d6564206f6620686176696e206c6f7374206869732074656d7065722e2048652066656c742074686174206865206f7567687420746f2068617665206469736461696d656420746861742064657370696361626c65207772657463682c2046796f646f72205061766c6f76697463682c20746f6f206d75636820746f2068617665206265656e2075707365742062792068696d20696e20466174686572205a6f7373696d6127732063656c6c2c20616e6420736f20746f206861766520666f72676f7474656e2068696d73656c662e2022546568206d6f6e6b732077657265206e6f7420746f20626c616d652c20696e20616e7920636173652c22206865207265666c63657465642c206f6e207468652073746570732e2022416e64206966207468657927726520646563656e742070656f706c6520686572652028616e642074686520466174686572205375706572696f722c204920756e6465727374616e642c2069732061206e6f626c656d616e2920776879206e6f7420626520667269656e646c7920616e6420636f757274656f757320776974687468656d3f204920776f6e27742061726775652c2049276c6c2066616c6c20696e20776974682065766572797468696e672c2049276c6c2077696e207468656d20627920706f6c69746e6573732c20616e642073686f77207468656d20746861742049277665206e6f7468696e6720746f20646f20776974682074686174204165736f702c207468746120627566666f6f6e2c20746861742050696572726f742c20616e642068617665206d6572656c79206265656e2074616b6b656e20696e206f7665722074686973206166666169722c206a757374206173207468657920686176652e22";
	string encoded = Hex::Encode((unsigned char *) str_long.c_str(), str_long.size());
	string decoded = Hex::Decode(str_long_hex);
	EXPECT_STREQ(encoded.c_str(), str_long_hex.c_str());
	EXPECT_STREQ(decoded.c_str(), str_long.c_str());
}

TEST(Hex, Empty) {
	string empty;
	string encoded = Hex::Encode((unsigned char *) empty.c_str(), empty.size());
	string decoded = Hex::Decode(empty);
	EXPECT_STREQ(encoded.c_str(), empty.c_str());
	EXPECT_STREQ(decoded.c_str(), empty.c_str());
}

TEST(Hex, BadLength) {
	string bad_len = "04340";
	EXPECT_NO_THROW(Hex::Encode((unsigned char *) bad_len.c_str(), bad_len.size()));
	ASSERT_THROW(Hex::Decode(bad_len), std::invalid_argument);
}

}

