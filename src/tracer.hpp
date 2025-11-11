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

using namespace std;

void tracer(pid_t pid, string pathname);


#endif