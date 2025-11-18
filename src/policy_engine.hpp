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

#pragma once

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
	long stub_return = 0;
};

class PolicyEngine {
	private:
		static int count;
		static unordered_map<int, struct Policy> policies; // key = id, value = struct
		static ACTION_TYPE compile_handler(struct Policy policy);
		ACTION_TYPE parse_action(const string &action_str);
		
		static string variant_to_string(const variant<int, string>& v);
	public:
		void load_policies_from_json();
		PolicyEngine(); // compile policies and store in policies hashmap
		Policy evaluate(int syscall_no);
		void reload();
		bool should_trace(int syscall_no);  // determin if we should bother evaluting this syscall
		//Action executions
		void modify_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy);
		void deny_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy);
		bool check_conditions(pid_t target, Policy policy, struct user_regs_struct regs);
		
		json variant_to_json(const variant<int, string> &v);
		void add_commands();
		void create_policy();
		void list_policies();
		void remove_policy();
		void edit_policy();
		json policy_to_json(Policy p);
};

extern string policy_config;
extern PolicyEngine policy_engine;



#endif