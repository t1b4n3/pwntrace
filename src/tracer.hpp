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
#include <variant>
#include <optional>
#include <stdexcept>

#include "./logging.hpp"
#include "./memory.hpp"
#include "./syscall_table.hpp"
#include "./policy_engine.hpp"

using namespace std;
using namespace nlohmann;
using std::get;
using std::holds_alternative;

typedef enum {
	SYSCALL_ENTRY, 
	SYSCALL_EXIT,
} SYSCALL;


void print_syscall(SYSCALL sys, pid_t target, PolicyEngine policy_engine);

void tracer(pid_t pid, string pathname);


#endif