#ifndef OPENSSLEXCEPTION_H_
#define OPENSSLEXCEPTION_H_

#include <openssl/err.h>
#include <iostream>
#include <sstream>
#include <vector>
using namespace std;

class OpensslException: public std::exception {

	typedef unsigned long error_code;

	string msg;
	vector<error_code> errors;

public:

	/**
	 * build a short error message,
	 * save and clear current openssl error codes
	 * @param msg short error description
	 */
	OpensslException(string msg);

	virtual ~OpensslException();

	/**
	 * get short error message
	 * @return short error message
	 */
	const char* what() const noexcept;

	/**
	 * print the short error message and all the openssl errors that match the saved codes.
	 * @param os a stream where the error message will be printed to
	 */
	void printExtendedInformation(ostream &os=cerr) const;
};

#endif /* OPENSSLEXCEPTION_H_ */
