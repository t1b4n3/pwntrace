#include "syscall_table.hpp"

unordered_map<int, string> SyscallTable::syscall_names;

SyscallTable::SyscallTable() {
	const char* possible_paths[] = {
        	"/usr/include/asm/unistd_64.h",
        	"/usr/include/x86_64-linux-gnu/asm/unistd_64.h", 
        	"/usr/include/asm/unistd.h",
        	"/usr/include/x86_64-linux-gnu/asm/unistd.h",
        	"/usr/include/bits/syscall.h",
        	nullptr
    	};

	// get archittecture
	char arch[0x32];
	struct utsname buffer;
	if (uname(&buffer) != 0) strcpy(arch, "Unknown"); 
	else snprintf(arch, 0x31, "%s", buffer.machine);
	
	for (int i = 0; possible_paths[i] != nullptr; i++) {
		ifstream file(possible_paths[i]);
		if (file.is_open()) {
			parse_header_file(possible_paths[i]);
			file.close();
			if (!syscall_names.empty()) return;
		}
	}

}

void SyscallTable::parse_header_file(const string& filename) {
	ifstream file(filename);
	if (!file.is_open()) return;
	string line;
	regex pattern(R"(\#define\s+__NR_(\w+)\s+(\d+))");
	while (getline(file, line)) {
		smatch matches;
		if (regex_search(line, matches, pattern)) {
			if (matches.size() == 3) {
				string name = matches[1];
				int number = stoi(matches[2]);
				syscall_names[number] = name;
			}
		}
	}
}

string SyscallTable::get_syscall_name(int syscall_num) {
	auto it = syscall_names.find(syscall_num);
	if (it != syscall_names.end()) {
		return it->second;
	}
	return "Unknown syscall : " + to_string(syscall_num);
}
