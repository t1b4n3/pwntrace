#include "print_syscall.hpp"

struct user_regs_struct pregs;
pid_t ptarget; 
ReadMemory pread_mem;
WriteMemory pwrite_mem;
SyscallTable ptable;


void PrintSyscall::pexecve() {

}

void PrintSyscall::pwrite() {
	printf("[+] Syscall %llu - %s\n( rdi=0x%llx rsi=0x%llx rdx=0x%llx )\nWrote Data : 0x%llx -> %s\n",
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), 
	pregs.rdi, pregs.rsi, pregs.rdx, pregs.rsi, 
	pread_mem.read_string(ptarget, pregs.rsi).c_str());
}

void PrintSyscall::pclose() {
	printf("[+] Syscall %llu - %s(0x%llx)\n",
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), 
	pregs.rdi
	);
}

void PrintSyscall::pread() {
	printf("[+] Syscall %llu - %s\n(0x%llx) Enter Data : 0x%llx -> ", 
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(), 
	pregs.rdi, pregs.rsi);
}

void PrintSyscall::update(struct user_regs_struct REGS, pid_t pid) {
	pregs = REGS;
	ptarget = pid;
}

void PrintSyscall::popen() {
	printf("[+] Syscall %llu - %s\nOpening : %s Flags : %d",
	pregs.orig_rax, ptable.get_syscall_name(pregs.orig_rax).c_str(),
	pread_mem.read_string(ptarget, pregs.rsi, 256), pregs.rdx
	);
}