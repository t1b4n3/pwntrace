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

#include "./syscall_table.hpp"
#include "./memory.hpp"
#include "./tracer.hpp"
#include "./logging.hpp"


using namespace std;


static void usage(const char* prog) {
    cerr << "Usage: " << prog << " -binary /path/to/program  OR  -pid <pid> -config ./path/to/config\n";
    cerr << "Example: sudo " << prog << " -binary /bin/ls -config ./policy.json\n";
    cerr << "         sudo " << prog << " -pid 1234 -config ./policy.json\n";
}

int main(int argc, char* argv[]) {
	if (argc < 5) {
		usage(argv[0]);
		exit(0);
	}
	pid_t pid = -1;
	string pathname, config_path;
	
	if (strcmp(argv[1], "-pid") == 0)
        	pid = atoi(argv[2]);
    	else if (strcmp(argv[1], "-binary") == 0)
    	    	pathname = argv[2];
    	else {
    	    	cerr << "Invalid option\n";
    	    	return 1;
    	}
	
	if (strcmp(argv[3], "-config") == 0) {
		config_path = argv[4];
	} else {
		usage(argv[0]);
		exit(0);
	}



	if (pid == -1 && pathname.empty()) {
		cerr << "[-] No valid mode selected." << endl;
		usage(argv[0]);
		return 1;
	} else {
		set_logfile_path("./pwntrace_logs");
		tracer(pid, pathname, config_path);
	}

	return 0;
}