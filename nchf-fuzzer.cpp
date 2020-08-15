#include <string>
#include <map>
#include <fstream>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/crc.hpp>

using namespace std;
using namespace boost;
using namespace boost::multiprecision;
using u256 = uint256_t;

namespace {
	enum class HashAlgorithm
	{
		DJB2,
		CRC32
	};
	string hashAlgName(HashAlgorithm alg)
	{
		switch (alg)
		{
			case HashAlgorithm::DJB2:
				return "DJB2";
			case HashAlgorithm::CRC32:
				return "CRC32";
		}
	}
}

static map<u256, pair<string, HashAlgorithm>> s_hashMap = {};

struct NCHFCollision
{
	string printStringAsHex(string const& input)
	{
		ostringstream os;
		for (auto const& c: input)
			os << hex << setfill('0') << setw(2) << right << int(c);
		return os.str();
	}

	void printCollision(HashAlgorithm alg, u256 hash, string input)
	{
		// Append to a local file in the same directory
		// as the fuzzer binary
		ofstream f("NCHF-Collision.txt", ios::app);
		f << endl;
		f << "Algorithm: " << hashAlgName(alg) << endl;
		f << "Hash: " << hash << endl;
		f << "Input 1: " << printStringAsHex(s_hashMap[hash].first) << endl;
		f << "Input 2: " << printStringAsHex(input) << endl;
	}

	bool operator()(HashAlgorithm alg, u256 hash, string input)
	{
		bool Collision = s_hashMap.count(hash) &&
			input != s_hashMap[hash].first &&
			alg == s_hashMap[hash].second;

		if (Collision)
		{
			printCollision(alg, hash, input);
			return true;
		}
		else
		{
			s_hashMap.emplace(hash, make_pair(input, alg));
			return false;
		}
	}
};

struct NCHF
{
	bool operator()(const uint8_t *data, size_t size, HashAlgorithm alg)
	{
		return NCHFCollision{}(
			alg,
			computeHash(data, size),
			string(data, data + size)
		);
	}

	virtual u256 computeHash(const uint8_t *data, size_t size) = 0;
};

struct DJB2: NCHF
{
	u256 computeHash(const uint8_t *data, size_t size) override
	{
		string input(data, data + size);
		u256 hash = 5381;
		for (auto c: input)
			hash = (hash << 5) + hash + c;
		return hash;
	}
};

struct CRC32: NCHF
{
	u256 computeHash(const uint8_t *data, size_t size) override
	{
		string input(data, data + size);
		crc_32_type hash;
		hash.process_bytes(input.c_str(), input.size());
		return hash.checksum();
	}
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
//	assert(!DJB2{}(data, size, HashAlgorithm::DJB2));
	assert(!CRC32{}(data, size, HashAlgorithm::CRC32));
	return 0;
}
