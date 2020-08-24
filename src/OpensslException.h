#ifndef OPENSSLEXCEPTION_H_
#define OPENSSLEXCEPTION_H_

#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <vector>
using namespace std;

class OpensslException: public std::exception {
	string msg;
	vector<unsigned long> errors;
	string extended_output;
public:
	OpensslException(string msg);
	virtual ~OpensslException();
	const char* what() const noexcept;
	const string &extended();
};

#endif /* OPENSSLEXCEPTION_H_ */
