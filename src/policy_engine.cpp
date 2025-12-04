#include "policy_engine.hpp"

//void set_policy_cmd() {
//	auto& pol GlobalCLI.add_group("policy");
//	pol.add("allow", "allow system calls to execute", [&](auto args){
//		cout << "allow" << endl;
//	});
//
//	pol.add("deny"< "deny system call from executing", [&](auto args) {
//		
//	});
//}

string policy_config;
PolicyEngine policy_engine;
int PolicyEngine::count;
unordered_map<int, struct Policy> PolicyEngine::policies;

PolicyEngine::PolicyEngine() {
	add_commands();
}

void PolicyEngine::add_pwntrace_json() {
	const char* home = getenv("HOME");
	policy_config = string(home) + "/.pwntrace.json";
	ifstream file(policy_config);
	if (file.is_open()) {
		file.close();
		return;
	} 
	file.close();
	ofstream outfile(policy_config);
	outfile << "[]";
	outfile.close();
	// add a empty json file

}

ACTION_TYPE PolicyEngine::parse_action(const string &action_str) {
    	if (action_str == "allow") return ACTION_TYPE::ALLOW;
    	else if (action_str == "deny") return ACTION_TYPE::DENY;
    	else if (action_str == "modify") return ACTION_TYPE::MODIFY;
    	else if (action_str == "stub") return ACTION_TYPE::STUB;
	else return ACTION_TYPE::ALLOW;
}

void PolicyEngine::reload() {
    	policies.clear();
    	load_policies_from_json();
}

void PolicyEngine::load_policies_from_json() {
	add_pwntrace_json();
    	string path = policy_config;
	ifstream file(path);
	if (!file.is_open()) {
		cerr << "[-] Could not open config file: " << policy_config << endl;
		return;
	}
    	json j;
    	file >> j;
	count = 0;

	SyscallTable table;

    	for (auto &item : j) {
    	    	Policy p;
		int id = item["id"];
		auto it = policies.find(id);
		if (it != policies.end()) continue;
    	    	p.id = id;
    	    	p.syscall = item["syscall"];
    	    	p.syscall_no = table.get_syscall_no(item["syscall"]);
    	    	p.action = parse_action(item.value("action", "allow"));
    	    	p.enabled = item.value("enabled", true);
    	    	p.stub_return = item.value("stub_return", 0xffffffffffffffff);
		p.use_conditions = item.value("use_conditions", false);
		count++;
		if (item.contains("arguments")) {
			auto &arg = item["arguments"];
			if (arg["rdi"].is_string()) {
				p.args.rdi = arg["rdi"].get<string>();
			} else if (arg["rdi"].is_number_integer()) {
				p.args.rdi = arg["rdi"].get<long>();
			} else if (arg["rdi"].is_null()) {
				p.args.rdi = long(-1);
			} else {
				p.args.rsi = arg["rdi"].dump();
			}

			if (arg["rsi"].is_string()) {
				p.args.rsi = arg["rsi"].get<string>();
			} else if (arg["rsi"].is_number_integer()) {
				p.args.rsi = arg["rsi"].get<long>();
			} else {
				p.args.rsi = arg["rsi"].dump();
			}
			if (arg["rdx"].is_string()) {
				p.args.rdx = arg["rdx"].get<string>();
			} else if (arg["rdx"].is_number_integer()) {
				p.args.rdx = arg["rdx"].get<long>();
			} else {
				p.args.rdx = arg["rdx"].dump();
			}
			if (arg["r10"].is_string()) {
				p.args.r10 = arg["r10"].get<string>();
			} else if (arg["r10"].is_number_integer()) {
				p.args.r10 = arg["r10"].get<long>();
			} else {
				p.args.r10 = arg["r10"].dump();
			}
		} else {
			p.args.r10 = long(-1);
			p.args.rdi = long(-1);
			p.args.rdx = long(-1);
			p.args.rsi = long(-1);
		}


		if (item.contains("conditions")) {
			auto &arg = item["conditions"];
			string operator_t = arg["operator"];
			if (operator_t == "=") {
				p.conditions.operator_t = OPERATOR_T::EQUAL;
			} else if (operator_t == ">") {
				p.conditions.operator_t = OPERATOR_T::GREATER;
			} else if (operator_t == "<") {
				p.conditions.operator_t = OPERATOR_T::LESSER;
			} else if (operator_t == "<=") {
				p.conditions.operator_t = OPERATOR_T::EQUAL_LESSER;
			} else if (operator_t == ">=") {
				p.conditions.operator_t = OPERATOR_T::EQUAL_GREATER;
			} else {
				p.use_conditions = false;
			}

			string field = arg["field"];
			if (field == "rdi") {
				p.conditions.field = FIELD::rdi;
			} else if (field == "rsi") {	
				p.conditions.field = FIELD::rsi;
			} else if (field == "rdx") {
				p.conditions.field = FIELD::rdx;
			} else if (field == "r10") {
				p.conditions.field = FIELD::r10;
			} else {
				p.use_conditions = false;
			}

			if (arg["value"].is_string()) {
				p.conditions.value = arg["value"].get<string>();
			} else if (arg["value"].is_number_integer()) {
				p.conditions.value = arg["value"].get<long>();
			}

		}

    	    	policies[p.syscall_no] = p;
		
    	}
}

bool PolicyEngine::should_trace(int syscall_no) {
    static const unordered_set<int> skip = {
        //9, 12, 39, 104, 105, 106, 107, 108, 108, 110, 112, 113, 114, 231, 238, 262, 334, 273, 10, 158, 318, 302, 218, 17, 11
    };
    return skip.find(syscall_no) == skip.end();
}

Policy PolicyEngine::evaluate(int syscall_no) {
	if (!should_trace(syscall_no)) return {.action = ACTION_TYPE::ALLOW};
	//unordered_map<int, struct Policy> policies;
	auto it = policies.find(syscall_no); 
	if (it == policies.end()) return {.action = ACTION_TYPE::ALLOW};

	Policy &p = it->second;
	if (!p.enabled) return {.action = ACTION_TYPE::ALLOW};	
	return p;
}

void PolicyEngine::stub_syscall(pid_t target, struct user_regs_struct regs, Policy policy) {
	cout << "\n[-] STUB : " << policy.syscall_no;
}

void PolicyEngine::deny_syscall(pid_t target, struct user_regs_struct regs, Policy policy) {
	printf("\n[-] DENY : %d - %s\n", policy.syscall_no, policy.syscall.c_str());
	regs.orig_rax = -1;
	regs.rax = policy.stub_return;
	ptrace(PTRACE_SETREGS, target, 0, &regs);
}


bool PolicyEngine::check_conditions(pid_t target, Policy policy, struct user_regs_struct regs) {
	ReadMemory read_mem;
	long long register_t = 0;
	switch (policy.conditions.field) {
		case FIELD::rdi:
			register_t = regs.rdi;
			break;
		case FIELD::rdx:
			register_t = regs.rdx;
			break;
		case FIELD::rsi:
			register_t = regs.rsi;
			break;
		case FIELD::r10:
			register_t = regs.r10;
			break;
		default:
			return false;
	}

	if (policy.conditions.operator_t == OPERATOR_T::EQUAL) {
		if (holds_alternative<long>(policy.conditions.value)) {
			return  static_cast<long>(register_t) == get<long>(policy.conditions.value);
		} else if (holds_alternative<string>(policy.conditions.value)) {
			string reg_value = read_mem.read_string(target, register_t);
			return reg_value == get<string>(policy.conditions.value);
		} else {
			return false;
		}
	} else if (policy.conditions.operator_t == OPERATOR_T::GREATER) {
		if (holds_alternative<long>(policy.conditions.value)) {
			return  get<long>(policy.conditions.value) > static_cast<long>(register_t);
		} else {
			return false;
		}
	} else if (policy.conditions.operator_t == OPERATOR_T::LESSER) {
		if (holds_alternative<long>(policy.conditions.value)) {
			return  get<long>(policy.conditions.value) < static_cast<long>(register_t);
		} else {
			return false;
		}
	} else if (policy.conditions.operator_t == OPERATOR_T::EQUAL_GREATER) {
		if (holds_alternative<long>(policy.conditions.value)) {
			return  get<long>(policy.conditions.value) >= static_cast<long>(register_t);
		} else {
			return false;
		}
	} else if (policy.conditions.operator_t == OPERATOR_T::EQUAL_LESSER) {
		if (holds_alternative<long>(policy.conditions.value)) {
			return  get<long>(policy.conditions.value) <= static_cast<long>(register_t);
		} else {
			return false;
		}
	}
	return false; 
}





void PolicyEngine::modify_register(pid_t target, unsigned long long &addr_to_write, variant<long, string>& value) {
	WriteMemory write_mem;
	if (holds_alternative<long>(value)) {
		long v = get<long>(value);
		if (v != -1) {
			addr_to_write = v;
		} else {
			return;
		}
	} else if (holds_alternative<string>(value)) {
		if (is_user_address(static_cast<uint64_t>(addr_to_write))) {
			write_mem.write_string(target, static_cast<uint64_t>(addr_to_write), get<string>(value));
		} else {
			uint64_t new_addr = write_mem.alloc_memory(target, get<string>(value).size() + 1);
			write_mem.write_string(target, new_addr, get<string>(value));
			addr_to_write = new_addr;
		}	
	}
}


void PolicyEngine::modify_syscall(pid_t target, struct user_regs_struct regs, Policy policy) {
	if (policy.use_conditions) {
		if (!check_conditions(target, policy, regs)) {
			cout << "\n[-] CONDITIONS NOT MET\n";
			return;
		}
	}
	struct user_regs_struct saved = regs;
	//ptrace(PTRACE_GETREGS, target, nullptr, &saved);
	ReadMemory read_mem;
	WriteMemory write_mem;
	cout << endl;
	//cout << "[*] MODIFY | " <<  policy.syscall
	//<< "(0x" << hex << regs.rdi << "=" << read_mem.read_string(target, regs.rdi)
	//<< ", 0x" << hex << regs.rsi << "=" << read_mem.read_string(target, regs.rsi)
	//<< ", 0x" << hex << regs.rdx << "=" << read_mem.read_string(target, regs.rdx) << ")"; //<< endl;

	modify_register(target, regs.rdi, policy.args.rdi);
	modify_register(target, regs.rsi, policy.args.rsi);
	modify_register(target, regs.rdx, policy.args.rdx);
	modify_register(target, regs.r10, policy.args.r10);

	ptrace(PTRACE_SETREGS, target, nullptr, &regs);
	// execute_syscall
	int status;
	ptrace(PTRACE_SYSCALL, target, 0, 0);
	waitpid(target, &status, 0);

	// exit;
	if (policy.stub_return != 0xffffffffffffffff) {
		regs.rax = static_cast<unsigned long long>(policy.stub_return);
		ptrace(PTRACE_SETREGS, target, nullptr, &regs);
	}
	
	ptrace(PTRACE_SYSCALL, target, 0, 0);
	waitpid(target, &status, 0);

	cout << "[*] MODIFY | " <<  policy.syscall
	<< "(0x" << hex << saved.rdi << "=" << read_mem.read_string(target, saved.rdi) << " -> 0x" << regs.rdi << "=" << read_mem.read_string(target, regs.rdi)
	<< ", 0x" << hex << saved.rsi << "=" << read_mem.read_string(target, saved.rsi) << " -> 0x" << regs.rsi << "=" << read_mem.read_string(target, regs.rsi)
	<< ", 0x" << hex << saved.rdx << "=" << read_mem.read_string(target, saved.rdx) << " -> 0x" << regs.rdx << "=" << read_mem.read_string(target, regs.rdx) <<
	 ")"; // << endl;
	//<<  " = 0x" << hex << ret << endl;

	//ptrace(PTRACE_SETREGS, target, nullptr, &saved);
}

void PolicyEngine::create_policy() {
	Policy p;
	p.id = ++count;
    	cout << "=== Add New Policy ===\n";

    	// syscall
    	cout << "Enter syscall: ";
    	cin >> p.syscall;
	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');


    	// action
	string action;
    	cout << "Action (allow/deny/modify/stub): ";
    	cin >> action;
	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	
	if (action == "allow") {
		p.action = ACTION_TYPE::ALLOW;
	} else if (action == "deny") {
		p.action = ACTION_TYPE::DENY;
	} else if (action == "modify") {
		p.action = ACTION_TYPE::MODIFY;
	} else if (action == "stub") {
		p.action = ACTION_TYPE::STUB;
	}
    	// enabled
    	cout << "Enable this policy? (1=yes, 0=no): ";
    	cin >> p.enabled;
	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	
	string stub;
	cout << "Stub return:(stub, no) ";
	cin >> stub;
	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

	if (stub == "no") {
		p.stub_return = 0xffffffffffffffff;
	} else {
		p.stub_return = stol(stub);
	}

	// modify arguments only if modify
    	if (p.action == ACTION_TYPE::MODIFY) {
    	    	cout << "System call Arguments:\n";
		auto ask_arg = [&](const string &name) -> variant<long, string> {
    	        	cout << name << " (value or -1 to skip): ";
    	        	string input;
    	        	getline(cin, input);
    	        	try {
    	        	    	return stoi(input);
    	        	} catch (...) {
    	        	    	return input;
    	        	}
    		};

    		p.args.rdi =  ask_arg("rdi");
    		p.args.rsi =  ask_arg("rsi");
    		p.args.rdx =  ask_arg("rdx");
    		p.args.r10 =  ask_arg("r10");
    	}
	
    	cout << "Use conditions? (1=yes, 0=no): ";
    	cin >> p.use_conditions;
	cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');


	string operator_t;
	string field;
    	if (p.use_conditions && (p.action == ACTION_TYPE::MODIFY || p.action == ACTION_TYPE::STUB)) {
		
        	cout << "Condition argument (rdi/rsi/rdx/r10): ";
		getline(cin, field);
		if (field == "rdi") p.conditions.field = FIELD::rdi;
		else if (field == "rsi") p.conditions.field = FIELD::rsi;
		else if (field == "rdx") p.conditions.field = FIELD::rdx;
		else if (field == "r10") p.conditions.field = FIELD::r10;

		
        	cout << "Operator (=/</>/<=/>=): ";
        	getline(cin, operator_t);
		if (operator_t == "=") p.conditions.operator_t = OPERATOR_T::EQUAL;
		else if (operator_t == ">=") p.conditions.operator_t = OPERATOR_T::EQUAL_GREATER;
		else if (operator_t == "<=") p.conditions.operator_t = OPERATOR_T::EQUAL_LESSER;
		else if (operator_t == ">") p.conditions.operator_t = OPERATOR_T::GREATER;
		else if (operator_t == "<") p.conditions.operator_t = OPERATOR_T::LESSER;

        	cout << "Condition value (int or string): ";
        	string raw;
		getline(cin, raw);
        	// detect int or string
        	try {
        	    	int v = stoi(raw);
        	    	p.conditions.value = v;
        	} catch (...) {
        	    	p.conditions.value = raw;
        	}
    	}
	
	json old_policy;

	// --- Load existing file ---
	{
	    	ifstream infile(policy_config);
		
	    	if (!infile.is_open()) {
	    	    old_policy = json::array();     // create empty list
	    	} else {
	    	    infile >> old_policy;
	    	}
	}

	// --- Ensure it's an array ---
	if (!old_policy.is_array()) {
	    // Convert object/single-policy into array
	    	json tmp = json::array();
	    	tmp.push_back(old_policy);
	    	old_policy = tmp;
	}

	// --- Create new policy ---
	json pjson;
	pjson["id"] = p.id;
	pjson["syscall"] = p.syscall;
	pjson["enabled"] = p.enabled;
	pjson["action"] = action;
	pjson["stub_return"] = p.stub_return;

	if (p.use_conditions && (ACTION_TYPE::MODIFY ||p.action == ACTION_TYPE::STUB)) {
	    	pjson["use_conditions"] = true;
		pjson["conditions"] = {
			{"operator", operator_t},
			{"value", variant_to_json(p.conditions.value)},
			{"field", field}
		};
	} else {
  	pjson["use_conditions"] = false;
	}

	if (p.action == ACTION_TYPE::MODIFY) {
	    	pjson["arguments"] = {
	    	    	{"rdi", variant_to_json(p.args.rdi)},
	    	    	{"rsi", variant_to_json(p.args.rsi)},
	    	    	{"rdx", variant_to_json(p.args.rdx)},
	    	    	{"r10", variant_to_json(p.args.r10)}
	    	};
	}
	// --- Append new entry ---
	old_policy.push_back(pjson);
	// --- Save file (overwrite with updated array) ---
	{
	    	ofstream outfile(policy_config, std::ios::trunc);
	    	outfile << old_policy.dump(4);
	}

	count++;
	reload();
}

json PolicyEngine::variant_to_json(const variant<long, string> &v) {
    	if (holds_alternative<long>(v))
    		return get<long>(v);
    	return get<string>(v);
}

string PolicyEngine::variant_to_string(const variant<long, string>& v) {
    if (holds_alternative<long>(v))
        return to_string(get<long>(v));

    return get<string>(v);
}



void PolicyEngine::add_commands() {
	auto& policy = GlobalCLI.add_group("policy");

	policy.add("add", "Add new policy", [&](auto args) {
		create_policy();
	});

	policy.add("reload", "Reload policy configuration file", [&](auto args) {
		reload();
	});

	policy.add("list","View all policies",  [&](auto args){
		list_policies();
	});

	policy.add("delete", "delete policy", [&](auto args){
		remove_policy();
	});

	policy.add("edit", "edit policy", [&](auto args){
		edit_policy();
	});	
}

void PolicyEngine::list_policies() {
	cout << "\n=== Existing Policies ===\n";
	reload();
    	if (policies.empty()) {
    	    	cout << "No policies found.\n";
    	    	return;
    	}
	
	for (const auto &entry : policies) {
		const Policy &p = entry.second;
		cout << "-----------------\n";
		cout << "ID: " << p.id << endl 
		<< "Syscall Name: " << p.syscall << endl
		<< "Syscall No: " << p.syscall_no << endl
		<< "Action: " << p.action << endl
		<< "Enabled: " << (p.enabled ? "true" : "false") << endl;

		
		if (p.action == ACTION_TYPE::MODIFY) {
			cout << "Arguments:";
            		cout << "\n        rdi = " << variant_to_string(p.args.rdi);
            		cout << "\n        rsi = " << variant_to_string(p.args.rsi);
            		cout << "\n        rdx = " << variant_to_string(p.args.rdx);
            		cout << "\n        r10 = " << variant_to_string(p.args.r10);
		}
		cout << endl;		
	}
}

void PolicyEngine::map_to_json() {
	for (const auto &entry : policies) {
		json old_policy;

		{
		    	ifstream infile(policy_config);

		    	if (!infile.is_open()) {
		    	    old_policy = json::array();     // create empty list
		    	} else {
		    	    infile >> old_policy;
		    	}
		}

		if (!old_policy.is_array()) {
		    // Convert object/single-policy into array
		    	json tmp = json::array();
		    	tmp.push_back(old_policy);
		    	old_policy = tmp;
		}

		json pjson;
		const Policy &p = entry.second;
		pjson["id"] = p.id;
		pjson["syscall"] = p.syscall;
		pjson["enabled"] = p.enabled;

		string action;
		switch (p.action) {
			case ACTION_TYPE::DENY:
				action = "deny";
				break;
			case ACTION_TYPE::MODIFY:
				action = "modify";
				break;
			case ACTION_TYPE::STUB:
				action = "stub";
				break;
			default:
				action = "allow";
		}

		string field;
		switch (p.conditions.field) {
			case FIELD::rdi:
				field = "rdi";
				break;
			case FIELD::rsi:
				field = "rsi";
				break;
			case FIELD::rdx:
				field = "rdx";
				break;
			case FIELD::r10:
				field = "r10";
				break;
		}

		pjson["action"] = action;
		pjson["stub_return"] = p.stub_return;

		if (p.use_conditions && (ACTION_TYPE::MODIFY ||p.action == ACTION_TYPE::STUB)) {
		    	pjson["use_conditions"] = true;
			pjson["conditions"] = {
				{"operator", p.conditions.operator_t},
				{"value", variant_to_json(p.conditions.value)},
				{"field", field}
			};
		} else {
  		pjson["use_conditions"] = false;
		}

		if (p.action == ACTION_TYPE::MODIFY) {
		    	pjson["arguments"] = {
		    	    	{"rdi", variant_to_json(p.args.rdi)},
		    	    	{"rsi", variant_to_json(p.args.rsi)},
		    	    	{"rdx", variant_to_json(p.args.rdx)},
		    	    	{"r10", variant_to_json(p.args.r10)}
		    	};
		}
		// --- Append new entry ---
		old_policy.push_back(pjson);
		// --- Save file (overwrite with updated array) ---
		{
		    	ofstream outfile(policy_config, std::ios::trunc);
		    	outfile << old_policy.dump(4);
		}
	}
}

void PolicyEngine::remove_policy() {
	if (policies.empty()) {
		cout << "No policies found\n"; 
	}
	cout << "Enter ID to delete: ";
	int id; 
	cin >> id;

	auto it = policies.find(id);
	if (it == policies.end()) {
		cout << "Policy not found\n";
		return;
	}
	policies.erase(it);
	count--;
	map_to_json();
}

void PolicyEngine::edit_policy() {
	Policy p;
    	cout << "=== Edit Policy ===\n";
}