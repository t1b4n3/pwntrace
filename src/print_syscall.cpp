#include "print_syscall.hpp"

struct user_regs_struct pregs;
pid_t ptarget; 
ReadMemory pread_mem;
WriteMemory pwrite_mem;
SyscallTable ptable;

/*
void PrintSyscall::pwrite() {
	printf("[+] Syscall %llu - %s(0x%llx, 0x%llx=%s, 0x%llx)\n",
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), 
	pregs.rdi, pregs.rsi, pread_mem.read_string(ptarget, pregs.rsi).c_str(), pregs.rdx);
}

void PrintSyscall::pclose() {
	printf("[+] Syscall %llu - %s(0x%llx)\n",
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), 
	pregs.rdi
	);
}

void PrintSyscall::pread() {
	printf("[+] Syscall %llu - %s(0x%llx)\nEnter Data : 0x%llx -> ", 
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), 
	pregs.rdi, pregs.rsi);
}

void PrintSyscall::popen() {
	printf("[+] Syscall %llu - %s(0x%llx)\nOpening : %s Flags : %d",
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), pregs.rsi,
	pread_mem.read_string(ptarget, pregs.rsi, 256), pregs.rdx
	);
}
*/

void PrintSyscall::update(struct user_regs_struct REGS, pid_t pid) {
	pregs = REGS;
	ptarget = pid;
}

void PrintSyscall::print_ret() {
	cout << " = 0x" << hex << pregs.rax << endl;
}

void PrintSyscall::pwrite() {
	cout << ptable.get_syscall_name(pregs.orig_rax)
              << "(" << "0x" << std::hex << pregs.rdi
              << ", 0x" << pregs.rsi << " = " 
              << pread_mem.read_string(ptarget, pregs.rsi)
              << ", 0x" << pregs.rdx << ")"; // reset decimal
}

void PrintSyscall::pclose() {
    	cout << ptable.get_syscall_name(pregs.orig_rax)
              << "(0x" << std::hex << pregs.rdi << ")";
}

void PrintSyscall::pread() {
    	cout << ptable.get_syscall_name(pregs.orig_rax)
              << "(0x" << std::hex << pregs.rdi << ")";
}

void PrintSyscall::popen() {
    	cout  << ptable.get_syscall_name(pregs.orig_rax)
              << "(0x" << std::hex << pregs.rsi << ") "
              << "Opening : " << pread_mem.read_string(ptarget, pregs.rsi, 256)
              << " Flags : " << std::dec << pregs.rdx;
}

void PrintSyscall::pexecve() {
	cout << ptable.get_syscall_name(pregs.orig_rax)
		<< "(0x" << hex << pregs.rdi << "=\"" << pread_mem.read_string(ptarget, pregs.rdi)
		<< "\", 0x" << hex << pregs.rsi << "=" << pread_mem.read_string(ptarget, pregs.rsi)
		<< ", 0x" << hex << pregs.rdx << "=" << pread_mem.read_string(ptarget, pregs.rdx) << ")";
}

void PrintSyscall::pexit() {
	cout << ptable.get_syscall_name(pregs.orig_rax)
		<< "(0x" << hex << pregs.rdi << ")";
}