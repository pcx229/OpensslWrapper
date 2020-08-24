
#include "OpensslException.h"

OpensslException::OpensslException(string msg) {
	stringstream ss;
	ss << "OpenSSL Error: " << msg;
	this->msg = ss.str();
	unsigned long err;
	while((err = ERR_get_error()) != 0) {
		errors.push_back(err);
	}
}

OpensslException::~OpensslException() {}

const char* OpensslException::what() const noexcept {
	return msg.c_str();
}

const string &OpensslException::extended() {
	if(extended_output.empty()) {
		stringstream ss;
		ss << msg << endl;
		vector<unsigned long>::const_iterator start = errors.begin(), end = errors.end();
		while(start != end) {
			unsigned long e = *start;
			ss << "error(id="<< hex << e << "):"
			   << "library: " << ERR_lib_error_string(e)
			   << ", in function: " << ERR_func_error_string(e)
			   << ", reason: " << ERR_reason_error_string(e) << endl;
			start++;
		}
		extended_output = ss.str();
	}
	return extended_output;
}

