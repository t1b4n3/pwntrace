#ifndef UI_H
#define UI_H

#pragma once
#include <iostream>
#include <string>
#include <unordered_map>
#include <functional>
#include <vector>
#include <sstream>
#include <readline/readline.h>
#include <readline/history.h>


using namespace std;

struct Command {
	string name;
	string description;
	function<void(const vector<string>&)> handler;
};

class CommandGroup {
	public:
		string name;
		static unordered_map<string, Command> commands;

		CommandGroup() : name("") {}

		CommandGroup(const string &name) : name(name) {}

		void add(const string cmd, const string desc, function<void(const vector<string>&)> fn);
		bool execute(const string cmd, const vector<string>& args) const;
};

class CLI {
	private:
		unordered_map<string, CommandGroup> groups;
		static char *cmd_generator(const char* text, int state);
		static char **cli_completion(const char* text, int start, int end);
		static string expand_home(const string& path);
	public:
		CLI() {}

		CommandGroup& add_group(const string& name);
		void parse_and_execute(const string& line);
		void cli();

};

extern CLI GlobalCLI;

#endif