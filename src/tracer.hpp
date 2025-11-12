#ifndef TRACER_HPP
#define TRACER_HPP

#include <iostream>
#include <cstdio>
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

#include "./logging.hpp"
#include "./memory.hpp"
#include "./syscall_table.hpp"
#include "./policy_engine.hpp"

using namespace std;
using namespace nlohmann;

typedef enum {
	SYSCALL_ENTRY, 
	SYSCALL_EXIT,
} SYSCALL;

vector<string> read_syscall_args(pid_t, int syscall_no, struct user_regs_struct regs);

void print_syscall(SYSCALL sys, pid_t target, PolicyEngine policy_engine);

void tracer(pid_t pid, string pathname, string config_path);

void modify_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy);

void deny_syscall(pid_t target, int syscall_no, Policy policy);


#endif