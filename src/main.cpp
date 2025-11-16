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

pid_t pid = -1;
string pathname;
string program_name;

static void help() {
    cerr << "Usage: " << program_name << " -binary /path/to/program  OR  -pid <pid> -config ./path/to/config\n";
    cerr << "Example: sudo " << program_name << " -binary /bin/ls -config ./policy.json\n";
    cerr << "         sudo " << program_name << " -pid 1234 -config ./policy.json\n";
}

bool is_config_loaded() {
	return !policy_config.empty();
}


void add_commands() {
	pid_t pid = -1;
	PolicyEngine engine;
	auto& run = GlobalCLI.add_group("run");
	auto& add = GlobalCLI.add_group("add");
	auto& hp = GlobalCLI.add_group("help");

	hp.add("_default", "help", [&](auto args){
		help();
	});

	add.add("_default", "add", [&](auto args){
		cout << "Defualt";
	});

	add.add("policy", "policy file", [&](auto args){
		if (args.empty()) {
			cout << "[-] Usage: add policy <path/to/policy.json>" << endl;
			return;
		}
		string tmp = args[0];
		if (access(tmp.c_str(), F_OK)) {
			cout << "[-] File no found || Permissions denied\n";
			return;
		}
		policy_config = tmp;
	});

	add.add("pid", "attach to a running pid", [&](auto args){
		if (args.empty()) {
			cout << "[-] Usage: add pid <PID>" << endl;
			return;
		}
		try {
			pid_t tmp = stoi(args[0]);
			pid = tmp;
		} catch (const exception &e) {
			cout << "[-] Invalid PID: " << args[0] << endl;
			return;
		}
	});

	add.add("bin", "start a new process", [&](auto args){
		if (args.empty()) {
			cout << "[-] Usage: add bin <path/to/binary>" << endl;
			return;
		}
		string tmp = args[0];
		if (access(tmp.c_str(), F_OK)) {
			cout << "[-] Executable no found || Permissions denied\n";
			return;
		}
		pathname = tmp;
	});





	run.add("_default", "run", [&](auto args){
		if (pathname.empty() || pid == -1) {
			cout << "[-] add binary or attach to running process first" << endl;
			return;
		}
		tracer(pid, pathname);
	});

	run.add("pid", "attach to a running pid", [&](auto args){
		if (args.empty()) {
			cout << "[-] Usage: run pid <PID>" << endl;
			return;
		}
		try {
			pid = stoi(args[0]);
		} catch (const exception &e) {
			cout << "[-] Invalid PID: " << args[0] << endl;
			return;
		}
		if (!is_config_loaded()) {
			cout << "[-] load policy file first" << endl;
			return;
		}
		tracer(pid, pathname);
	});

	run.add("bin", "start a new process", [&](auto args){
		if (args.empty()) {
			cout << "[-] Usage: run binary <path/to/binary>" << endl;
			return;
		}
		pathname = args[0];
		if (access(pathname.c_str(), F_OK)) {
			cout << "[-] Executable no found || Permissions denied\n";
			return;
		}
		if (!is_config_loaded()) {
			cout << "[-] load policy file first" << endl;
			return;
		}
		tracer(pid, pathname);
	});
}

int main(int argc, char* argv[]) {
	policy_config = "./pwntrace.json";
	policy_engine.load_policies_from_json();
	program_name = argv[0];
	add_commands();
	GlobalCLI.cli();	
	return 0;
}