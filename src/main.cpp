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
#include <nlohmann/json.hpp>

#include "./syscall_table.hpp"
#include "./memory.hpp"
#include "./tracer.hpp"
#include "./ui.hpp"
#include "./logging.hpp"
#include "./policy_engine.hpp"

using namespace std;
using namespace nlohmann;

string program_name;

bool is_config_loaded() {
	return !policy_config.empty();
}

int main(int argc, char* argv[]) {
	pid = -1;
	//policy_config = "./pwntrace.json";
	policy_engine.load_policies_from_json();
	program_name = argv[0];
	GlobalCLI.cli();	
	return 0;
}