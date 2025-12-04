#include "ui.hpp"

CLI GlobalCLI; 

//unordered_map<string, Command> CommandGroup::commands;
//unordered_map<string, CommandGroup> CLI::groups;



void CommandGroup::add(const string cmd, const string desc, 
	function<void(const vector<string>&)> fn) {
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
		cmdName = "_defualt";
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
	rl_attempted_completion_function = cli_completion;

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
		if (line.empty()) continue;
		if (line == "exit" || line == "q" || line == "quit") break;
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

