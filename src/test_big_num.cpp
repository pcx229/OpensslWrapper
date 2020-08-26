

#include <iostream>
using namespace std;

#include "big_num.h"
using namespace crypto;

void test_big_num() {

	BigNum a;

	// default

	cout << "- default value:" << endl;

	cout << "default number 'a' is " << a << endl;

	// explicit convention

	cout << endl << "- conventions:" << endl;

	a = 67;
	cout << "now 'a' is " << a << endl;
	a = "32438274923849038428403253422";
	cout << "and now 'a' is " << a << endl;

	// comparison

	cout << endl << "- comparisons:" << endl;

	cout << "a > 4 ? " << ((a > 4) ? "true" : "false") << endl;
	cout << "a < 4 ? " << ((a < 4) ? "true" : "false") << endl;
	cout << "a == 4 ? " << ((a == 4) ? "true" : "false") << endl;
	cout << "a != 4 ? " << ((a != 4) ? "true" : "false") << endl;

	// arithmetic

	cout << endl << "- arithmetic:" << endl;

	BigNum b("3B42C532A", BigNum::encoding::HEX);

	cout << "'b' is " << b << endl;

	cout << "a + 4 ? " << (a + 4) << endl;
	cout << "a - 4 ? " << (a - 4) << endl;
	cout << "a * 4 ? " << (a * 4) << endl;
	cout << "a / 4 ? " << (a / 4) << endl;
	cout << "a % 4 ? " << (a % 4) << endl;
	cout << "a + b ? " << (a + b) << endl;

	// increment + decrement

	cout << endl << "- increment + decrement:" << endl;

	cout << "a++ ? " << a++ << endl;
	cout << "a-- ? " << a-- << endl;

	// access

	cout << endl << "- access:" << endl;

	a = -9996576;
	cout << "as a negative number: " << *a << endl;
	a = 43249732;
	cout << "as a positive number: " << *a << endl;

	// copying

	cout << endl << "- copying:" << endl;

	cout << "'a' is " << a << endl;
	cout << "'b' is " << b << endl;
	b = a;
	cout << " (b = a) and now 'b' is " << b << endl;

	// print

	cout << endl << "- printing options:" << endl;

	cout << "'a' as hexadecimal ? ";
	a.print(cout, BigNum::encoding::HEX);
	cout << endl;
	cout << "'a' as decimal ? ";
	a.print(cout, BigNum::encoding::DEC);
	cout << endl;
	cout << "'a' as decimal with operator << ? " << a << endl;

}
