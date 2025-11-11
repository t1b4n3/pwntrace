#ifndef READ_MEMORY_HPP
#define READ_MEMORY_HPP

#include <cstdint>
#include <cstdlib>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <errno.h>
#include <cstring>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <unordered_map>
#include <sys/stat.h>
#include <filesystem>
#include <sys/utsname.h>
#include <fstream>
#include <regex>

using namespace std;


bool is_user_address(uint64_t addr);

class ReadMemory {
	public: 
	string read_string(pid_t pid, uint64_t addr, size_t maxlen = 256);
	vector<uint8_t> read_bytes(pid_t pid, uint64_t addr, size_t maxlen = 256);
	//string hexdump(const vector<uint8_t>& data, size_t max_display = 64); // show in proxy 
};

#endif