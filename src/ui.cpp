#include "ui.hpp"

CLI GlobalCLI; 

//unordered_map<string, Command> CommandGroup::commands;
//unordered_map<string, CommandGroup> CLI::groups;
static void help() {
	// add
	cout << "	=== Attach/Spawn process ===\n";
	cout << "	binary <path/to/binary>			Spawn a new process\n";
	cout << "	pid <pid>				Attach a process\n";
	cout << "	=== Policy ===\n";
	cout << "	policy add				Add a policy\n";
	cout << "	policy list				List available polices\n";
	cout << "	policy delete				Remove a policy\n";
	cout << "	policy edit				Edit a policy\n";
	cout << "	policy reload				Reload policy configuration file\n";
	cout << " 	policy view				View current policy file\n";
	cout << "	policy change				Change policy file\n";
	//cout << "	=== "
	
	
	
	cout << "	=== ===\n";
}


void CommandGroup::add(const string cmd, const string desc, function<void(const vector<string>&)> fn) {
	commands()[cmd] = Command{cmd, desc, fn};
}

bool CommandGroup::execute(const string cmd, const vector<string>& args) const {
	auto it = commands().find(cmd);
	if (it == commands().end()) return false;
	it->second.handler(args);
	return true;
}

void CLI::parse_and_execute(const string& line) {
	istringstream iss(line);
	string groupName, cmdName;
	iss >> groupName >> cmdName;

	auto it = groups().find(groupName);
	if (it == groups().end()) {
		cout << "[-] Unknown Group: " << groupName << endl;
		return;
	} 

	if (cmdName.empty()) {
		cmdName = "_default";
	}

	if (groupName.empty()) return;

	vector<string> args;
	string token;
	while (iss >> token) args.push_back(token);

	if (!it->second.execute(cmdName, args)) {
		cout << "[-] Unkown Command: " << cmdName << " in group " << groupName << endl;
	}

}

CommandGroup& CLI::add_group(const string& name) {
	//auto it = groups.find(name);
	//if (it == groups.end()) {
	//	auto inserted = groups.emplace(name,CommandGroup(name));
	//	return inserted.first->second;
	//}
	//return it->second;
    	auto [it, inserted] = groups().try_emplace(name, name);
    	return it->second;

}

void CLI::cli() {
	//rl_attempted_completion_function = cli_completion;

	string histfile = expand_home("~/.pwntrace.txt");

	using_history();
	read_history(histfile.c_str());
	char *input;
	while (true) {
		//cout << "[pwntrace]> ";
		input = readline("[pwntrace]> ");
		if (!input) break;
		string line(input);
		free(input);
		add_history(line.c_str());
		if (line.empty()) continue;
		if (line == "exit" || line == "q" || line == "quit") break;
		else if (strncmp(line.c_str(), "log-file", 8) == 0) {
			if (!line.starts_with("log-file ")) {
				cout << "[-] Usage: log-file <path/to/logfile\n";
				continue;
			}
			string tmp_file = line.substr(9);
			//tmp_file.pop_back();
			set_logfile_path(tmp_file.c_str());
			cout << "[+] log-file set to " << tmp_file << endl;
			continue;
		}
		else if (line == "help" || line == "h") {
			help();
			continue;
		}
		else if (strncmp(line.c_str(), "binary", 6) == 0) {
			if (!line.starts_with("binary ")) {
			   	cout << "[-] Usage: binary <path/to/binary>\n";
			   	continue;
			}

			string tmp = line.substr(7);
			tmp.pop_back();
			if (access(tmp.c_str(), F_OK)) {
				cout << "[-] Executable not found or permission denied\n";
			} else {
			   	pathname = tmp;
			}
			continue;
		} else if (strncmp(line.c_str(), "pid", 3) == 0) {
			pid_t tmp;
			if (!line.starts_with("pid ")) {
				cout << "[-] Usage: pid <pid>" << endl;
			}
			string tmp1 = line.substr(4);
			try {
				pid_t tmp2 = stoi(tmp1);
				pid = tmp2;
			} catch (const exception &e) {
				cout << "Invalid PID: " << tmp << endl;
			
			}
			continue;
		} else if (line == "run" || line == "r") {
			//tracer(pid, pathname);
			cout << "[=] Running binary : " << pathname << " || pid : " << pid << endl;
			cout << "=== 	===\n";
			tracer();
			continue;
		}
		parse_and_execute(line);
	}
	write_history(histfile.c_str());
}


void CLI::breakpoint_cli(string syscall) {
	//rl_attempted_completion_function = cli_completion;

	string histfile = expand_home("~/.pwntrace.txt");

	using_history();
	read_history(histfile.c_str());
	char *input;
	char *cmd;
	sprintf(cmd, "[pwntrace](%)> ", syscall.c_str());
	while (true) {
		
		input = readline(cmd);
		if (!input) break;
		string line(input);
		free(input);
		if (line.empty()) continue;
		if (line == "exit" || line == "q" || line == "quit") break;
		else if (line == "help" || line == "h") help();
		add_history(line.c_str());
		parse_and_execute(line);
	}
	write_history(histfile.c_str());
}


char *CLI::cmd_generator(const char* text, int state) {
	static size_t list_index;
	static std::vector<std::string> matches;
	if (state == 0) {  // first call
	    	matches.clear();
	    	list_index = 0;
	
	    	// Collect all possible commands from all groups
	    	for (const auto& [groupName, group] : GlobalCLI.groups()) {
	    	    	// Complete group names
	    	    	if (groupName.find(text) == 0)
	    	    	    matches.push_back(groupName);
			
	    	    	// Complete commands inside this group
	    	    	for (const auto& [cmdName, cmd] : group.commands()) {
	    	    	    std::string full = groupName + " " + cmdName;
	    	    	    if (full.find(text) == 0)
	    	    	        matches.push_back(full);
	    	    	}
	    	}
	}

	if (list_index < matches.size()) {
		return strdup(matches[list_index++].c_str());
	} else {
		return nullptr;
	}
}

char **CLI::cli_completion(const char* text, int start, int end) {
	(void)end;
	return rl_completion_matches(text, cmd_generator);
}

string CLI::expand_home(const string& path) {
	if (path[0] == '~') {
        	const char* home = getenv("HOME");
        	if (!home) home = "";
        	return std::string(home) + path.substr(1);
    	}
    	return path;
}

