#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <nlohmann/json.hpp> 

#include "syscall_table.hpp"


using namespace std;
using namespace nlohmann;

typedef enum {
	ALLOW,
	DENY,
	MODIFY,
	STUB,
	LOG_ONLY,
} ACTION_TYPE;

struct Policy {
	int id;
	string syscall;
	int syscall_no;
	ACTION_TYPE action;
	bool enabled;

	// optional fields
	string condition;
	string modify; 
	int stub_return = 0;
};

class PolicyEngine {
	private:
		static unordered_map<int, struct Policy> policies; // key = id, value = struct
		string config_path;
		static ACTION_TYPE compile_handler(struct Policy policy);
		ACTION_TYPE parse_action(const string &action_str);
		void load_policies_from_json(const string &path);
		 
	public:
		PolicyEngine(const string &config_pathname); // compile policies and store in policies hashmap
		Policy evaluate(int syscall_no);
		void reload();
		bool should_trace(int syscall_no);  // determin if we should bother evaluting this syscall
		
};

#endif