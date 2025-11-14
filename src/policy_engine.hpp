#ifndef POLICY_ENGINE_H
#define POLICY_ENGINE_H

#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <variant>
#include <optional>
#include <stdexcept>
#include <nlohmann/json.hpp> 

#include "ui.hpp"
#include "syscall_table.hpp"
#include "memory.hpp"


using namespace std;
using namespace nlohmann;

typedef enum {
	ALLOW,
	DENY,
	MODIFY,
	STUB,
	LOG_ONLY,
} ACTION_TYPE;



struct Conditions {
	string operator_;
	string field;
	variant<int, string> value; 
};

struct Policy {
	int id;
	string syscall;
	int syscall_no;
	ACTION_TYPE action;
	bool enabled;
	// optional fields
	bool use_conditions;
	Conditions conditions;
	vector<variant<int, string>> arguments;
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
	
		//Action executions
		void modify_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy);
		void deny_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy);
		bool check_conditions(pid_t target, Policy policy, struct user_regs_struct regs);
};

static void set_policy_cmd()__attribute__((constructor));

#endif