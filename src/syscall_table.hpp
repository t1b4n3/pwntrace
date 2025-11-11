#ifndef SYSCALL_TABLE_HPP
#define SYSCALL_TABLE_HPP

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


class SyscallTable {
	private:
		static unordered_map<int, string> syscall_names;
		

	public:
		SyscallTable();
		string get_syscall_name(int syscall_num);	
		static void parse_header_file(const string& filename);
};


#endif