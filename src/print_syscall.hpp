#ifndef PRINT_SYSCALLS_H
#define PRINT_SYSCALLS_H

#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <errno.h>
#include <cstdio>


#include "syscall_table.hpp"
#include "memory.hpp"

extern struct user_regs_struct pregs;
extern SyscallTable ptable;
extern ReadMemory pread_mem;
extern WriteMemory pwrite_mem;
extern pid_t ptarget;

class PrintSyscall {
	public:
		void update(struct user_regs_struct REGS, pid_t pid);
		void pwrite();
		void pread();
		void pclose();
		void pexecve();
		void popen();
};



#endif