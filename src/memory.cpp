#include "memory.hpp"

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
	if (!is_user_address(addr)) return "NULL";

	size_t read = 0;
	errno = 0;
	long word;
	int count = 0;
	while (read < maxlen) {
		word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr + read), NULL);
		if (word == -1 && errno != 0) break;
		uint8_t *bytes = reinterpret_cast<uint8_t*>(&word);
		for (size_t i = 0; i < sizeof(long) && read < maxlen; ++i, ++read) {
			if (bytes[i] == 0 && count == 0) return "NULL";
			if (bytes[i] == 0) return s;
			s.push_back(static_cast<char>(bytes[i]));
		}  
		count++;
	}
	return s;
}

long ReadMemory::read_int(pid_t pid, uint64_t addr) {
	if (!is_user_address(addr)) return -1;
	errno = 0;
	long word = ptrace(PTRACE_PEEKDATA, pid, (void*)(addr), NULL);
	if (word == -1 && errno != 0) return -1;
	return word;
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

//bool WriteMemory::modify_register(pid_t target, long register_t, variant<int, string> &value) {
//	if (!is_user_address(register_t)) return false;
//
//	if (holds_alternative<int>(value)) {
//		register_t = get<int>(value);
//	} else {
//		write_string(target, register_t, get<string>(value));
//	}
//	return true;
//}

void WriteMemory::write_string(pid_t target, uint64_t addr, string to_write) {
	if (!is_user_address(addr)) return;
	write_remote_memory(target, reinterpret_cast<void*>(addr), to_write.c_str(), to_write.size() + 1);
}

ssize_t WriteMemory::write_remote_memory(pid_t target, void *addr, const void *buf, size_t len) {
	errno = 0;
	size_t written = 0;
	size_t word_size = sizeof(long);
	const uint8_t *src = reinterpret_cast<const uint8_t*>(buf);
	uintptr_t dst = reinterpret_cast<uintptr_t>(addr);
	long data;
	size_t chunk = 0;
	while (written < len) {
		data = 0;
		chunk = min(word_size, len - written);

		memcpy(&data, src + written, chunk);

		if (ptrace(PTRACE_POKEDATA, target, (void*)(dst + written), (void*)data) == -1) return -1;
		written += chunk;
	}
	return static_cast<ssize_t>(written);
}


uint64_t WriteMemory::alloc_memory(pid_t target, size_t size) {
	struct user_regs_struct regs, saved;
	ptrace(PTRACE_GETREGS, target, nullptr, &saved);
	regs = saved;
	regs.orig_rax = 9; // mmap
	regs.rdi = 0;
	regs.rsi = size;
	regs.rdx = PROT_READ|PROT_WRITE|PROT_EXEC;
	regs.r10 = MAP_PRIVATE|MAP_ANONYMOUS;
	regs.r8 = -1;
	regs.r9 = 0;
	int status;
	ptrace(PTRACE_SETREGS, target, nullptr, &regs);
	//enter syscall
	ptrace(PTRACE_SYSCALL, target, 0, 0);
	waitpid(target, &status, 0);

	// exit syscall
	ptrace(PTRACE_SYSCALL, target, 0, 0);
	waitpid(target, &status, 0);

	// read result
	ptrace(PTRACE_GETREGS, target, nullptr, &regs);
	uint64_t addr = regs.rax;

	ptrace(PTRACE_SETREGS, target, nullptr, &saved);
	return addr;
}			