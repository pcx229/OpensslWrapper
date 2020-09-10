#ifndef ENCODER_H_
#define ENCODER_H_

#include <sstream>
#include <iostream>
using namespace std;

namespace crypto {

	typedef string bytes;
	typedef stringstream bytesstream;

	class Encoder {
		public:
			virtual ~Encoder() = 0;
	};

	class BlockEncoder : virtual public Encoder {
		public:
			virtual ~BlockEncoder() = 0;
			virtual bytes Encode(const bytes& data) = 0;
			virtual bytes Encode(const unsigned char *data, size_t length) = 0;
			virtual bytes Decode(const bytes& data) = 0;
	};

	class StreamEncoder : virtual public Encoder {
		public:
			virtual ~StreamEncoder() = 0;
			virtual ostream &Encode(istream &is) = 0;
			virtual ostream &Decode(istream &is) = 0;
	};
}

#endif
