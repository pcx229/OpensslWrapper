
#include "OpensslException.h"

OpensslException::OpensslException(string msg) {
	stringstream ss;
	ss << "OpenSSL Error: " << msg;
	this->msg = ss.str();
	error_code err;
	while((err = ERR_get_error()) != 0) {
		errors.push_back(err);
	}
}

OpensslException::~OpensslException() {}

const char* OpensslException::what() const noexcept {
	return msg.c_str();
}

void OpensslException::printExtendedInformation(ostream &os) const {
	os << msg << endl;
	vector<error_code>::const_iterator start = errors.begin(), end = errors.end();
	while(start != end) {
		error_code err = *start;
		os << "[error id="<< hex << err << "]"
		   << " library: " << ERR_lib_error_string(err)
		   << ", in function: " << ERR_func_error_string(err)
		   << ", reason: " << ERR_reason_error_string(err) << endl;
		start++;
	}
}
