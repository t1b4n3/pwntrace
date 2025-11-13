#ifndef MEMORY_HPP
#define MEMORY_HPP

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
#include <variant>

using namespace std;


bool is_user_address(uint64_t addr);

class ReadMemory {
	public: 
		string read_string(pid_t pid, uint64_t addr, size_t maxlen = 256);
		long read_int(pid_t pid, uint64_t addr);
		vector<uint8_t> read_bytes(pid_t pid, uint64_t addr, size_t maxlen = 256);
	//string hexdump(const vector<uint8_t>& data, size_t max_display = 64); // show in proxy 
};

class WriteMemory {
	public:
		void write_string(pid_t target, uint64_t addr, string to_write); 
		ssize_t write_remote_memory(pid_t target, void *addr, const void *buf, size_t len);
		//bool modify_register(pid_t target, long register, variant<long, string> &value);
};	


#endif