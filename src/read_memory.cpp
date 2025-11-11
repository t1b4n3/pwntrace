#include "read_memory.hpp"

bool is_user_address(uint64_t addr) {
	if (addr < 0x1000) return false; // likely kernel / NULL / invalid
#if defined(__x86_64__)
    // user-space canonical addresses for x86_64 typically below 0x00007fffffffffff
    	return addr <= 0x7fffffffffffULL;
#else
    // 32-bit user space: below 0xffffffff
    	return addr <= 0xffffffffUL;
#endif
}

string ReadMemory::read_string(pid_t pid, uint64_t addr, size_t maxlen) {
	string s;
	if (!is_user_address(addr)) return s;

	size_t read = 0;
	errno = 0;
	long word;

	while (read < maxlen) {
		word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + read), NULL);
		if (word == -1 && errno != 0) break;
		uint8_t *bytes = reinterpret_cast<uint8_t*>(&word);
		for (size_t i = 0; i < sizeof(long) && read < maxlen; ++i, ++read) {
			if (bytes[i] == 0) return s;
			s.push_back(static_cast<char>(bytes[i]));
		}  
	}
	return s;
}

vector<uint8_t> ReadMemory::read_bytes(pid_t pid, uint64_t addr, size_t maxlen) {
	vector<uint8_t> return_value;
	return_value.reserve(maxlen);
	size_t word_size = sizeof(long);
	size_t n_full = maxlen / word_size;
	size_t remainder = maxlen % word_size;

	errno = 0;
	long word;
	for (size_t i = 0; i < n_full; ++i) {
		word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + i * word_size), NULL);
		if (word == -1 && errno != 0) break;

		uint8_t *bytes = reinterpret_cast<uint8_t*>(&word);
		for (size_t j = 0; j < word_size; ++j) return_value.push_back(bytes[j]);
	}

	if (remainder) {
		word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + n_full * word_size), NULL);
		if (!(word == -1 && errno != 0)) {
			uint8_t *bytes = reinterpret_cast<uint8_t*>(&word);
			for (size_t j = 0; j < word_size; ++j) return_value.push_back(bytes[j]);
		}
	}
	return return_value;
}
