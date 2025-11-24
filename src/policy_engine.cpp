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

ACTION_TYPE PolicyEngine::parse_action(const string &action_str) {
    	if (action_str == "allow") return ACTION_TYPE::ALLOW;
    	else if (action_str == "deny") return ACTION_TYPE::DENY;
    	else if (action_str == "modify") return ACTION_TYPE::MODIFY;
    	else if (action_str == "stub") return ACTION_TYPE::STUB;
    	else return ACTION_TYPE::LOG_ONLY;
}

void PolicyEngine::reload() {
    	policies.clear();
    	load_policies_from_json();
}

void PolicyEngine::load_policies_from_json() {
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
    	    	p.id = item["id"];
    	    	p.syscall = item["syscall"];
    	    	p.syscall_no = table.get_syscall_no(item["syscall"]);
    	    	p.action = parse_action(item.value("action", "allow"));
    	    	p.enabled = item.value("enabled", true);
    	    	p.stub_return = item.value("stub_return", 0);
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
				throw runtime_error("Invalid type for argument rdi");
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


void PolicyEngine::deny_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy) {
	printf("\n[-] DENY : %d - %s\n", policy.syscall_no, policy.syscall.c_str());
	regs.orig_rax = -1;
	regs.rax = policy.stub_return;
	ptrace(PTRACE_SETREGS, target, 0, &regs);
}

/*
bool PolicyEngine::check_conditions(pid_t target, Policy policy, struct user_regs_struct regs) {
	if (policy.conditions.field.empty()) return true;
	long actual_value = 0;
    
	// check arg
    	if (policy.conditions.field == "rdi") {
#if defined(__x86_64__)
        actual_value = regs.rdi;
#elif defined(__i386__)
        actual_value = regs.ebx;
#endif
    	} else if (policy.conditions.field == "rsi") {
#if defined(__x86_64__)
        	actual_value = regs.rsi;
#elif defined(__i386__)
        	actual_value = regs.ecx;
#endif
    	}
    else if (policy.conditions.field == "rdx") {
#if defined(__x86_64__)
	        actual_value = regs.rdx;
#elif defined(__i386__)
        	actual_value = regs.edx;
#endif 
	}
	if (policy.conditions.operator_ == "equals") {
		if (holds_alternative<int>(policy.conditions.value)) {
			return actual_value == get<int>(policy.conditions.value); // 
		} else {
			ReadMemory read_mem;
			string mem_str = read_mem.read_string(target, actual_value, 256);
			return mem_str == get<string>(policy.conditions.value);
		}
	}
	return false;
}
*/

void PolicyEngine::modify_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy) {
	//if (policy.use_conditions) {
	//	if (!check_conditions(target, policy, regs)) return;
	//}
	struct user_regs_struct saved = regs;
	ReadMemory read_mem;
	WriteMemory write_mem;
	cout << "[*] MODIFY | " <<  policy.syscall
	<< "(0x" << hex << regs.rdi << "=" << read_mem.read_string(target, regs.rdi)
	<< ", 0x" << hex << regs.rsi << "=" << read_mem.read_string(target, regs.rsi)
	<< ", 0x" << hex << regs.rdx << "=" << read_mem.read_string(target, regs.rdx) << ")" << endl;

	if (holds_alternative<long>(policy.args.rdi)) {
		long value = get<long>(policy.args.rdi); 
		if (value != -1) {
			regs.rdi = value;
		}
	} else if (holds_alternative<string>(policy.args.rdi)){
		string str = get<string>(policy.args.rdi) + '\0';
		//uint64_t addr = write_mem.alloc_memory(target, str.size());
		write_mem.write_string(target, regs.rdi, str);
		//regs.rdi = addr;
	} 

	if (holds_alternative<long>(policy.args.rsi)) {
		if (get<long>(policy.args.rsi) != -1) {
			regs.rsi = get<long>(policy.args.rsi);
		}

	} else if (holds_alternative<string>(policy.args.rsi)) {
		//write_mem.write_string(target, regs.rsi, get<string>(policy.args.rsi)  + '\0');
		string str = get<string>(policy.args.rsi) + '\0';
		//uint64_t addr = write_mem.alloc_memory(target, str.size());
		write_mem.write_string(target, regs.rsi, str);
		//regs.rsi = addr;
		//cout << "rsi: " << hex << addr << " @ " << str << "\n";
	}

	if (holds_alternative<long>(policy.args.rdx)) {
		if (get<long>(policy.args.rdx) != -1) {
			regs.rdx = get<long>(policy.args.rdx);
		}

	} else if (holds_alternative<string>(policy.args.rdx)) {
		//write_mem.write_string(target, regs.rdx, get<string>(policy.args.rdx) + '\0');
		string str = get<string>(policy.args.rdx) + '\0';
		//uint64_t addr = write_mem.alloc_memory(target, str.size());
		write_mem.write_string(target, regs.rdx, str);
		//regs.rdx = addr;
	}
	if (holds_alternative<long>(policy.args.r10)) {
		if (get<long>(policy.args.r10) != -1) {
			regs.r10 = get<long>(policy.args.r10);
		}

	} else if (holds_alternative<string>(policy.args.r10)) {
		//write_mem.write_string(target, regs.r10, get<string>(policy.args.r10) + '\0');
		string str = get<string>(policy.args.r10) + '\0';
		uint64_t addr = write_mem.alloc_memory(target, str.size());
		write_mem.write_string(target, addr, str);
		regs.r10 = addr;
	}

	ptrace(PTRACE_SETREGS, target, nullptr, &regs);
    	//printf("[*] MODIFY: %d - %s\n(0x%llx, 0x%llx, 0x%llx) mem[(%s), (%s), (%s)]",
	//	policy.syscall_no, policy.syscall.c_str(),
	//	regs.rdi, regs.rsi, regs.rdx, read_mem.read_string(target, regs.rdi).c_str(),
	//	read_mem.read_string(target, regs.rsi), read_mem.read_string(target, regs.rdx)
	//);
	cout << "[**] MODIFICATION | " <<  policy.syscall
	<< "(0x" << hex << regs.rdi << "=" << read_mem.read_string(target, regs.rdi)
	<< ", 0x" << hex << regs.rsi << "=" << read_mem.read_string(target, regs.rsi)
	<< ", 0x" << hex << regs.rdx << "=" << read_mem.read_string(target, regs.rdx) << ")\n";

	ptrace(PTRACE_SETREGS, target, nullptr, &saved);

	cout << "[*] After MODIFICATION | " <<  policy.syscall
	<< "(0x" << hex << regs.rdi << "=" << read_mem.read_string(target, regs.rdi)
	<< ", 0x" << hex << regs.rsi << "=" << read_mem.read_string(target, regs.rsi)
	<< ", 0x" << hex << regs.rdx << "=" << read_mem.read_string(target, regs.rdx) << ")";




}

void PolicyEngine::create_policy() {
	Policy p;
	p.id = ++count;
    	cout << "=== Add New Policy ===\n";

    	// syscall
    	cout << "Enter syscall: ";
    	cin >> p.syscall;

    	// action
	string action;
    	cout << "Action (allow/deny/modify): ";
    	cin >> action;
	
	if (action == "allow") {
		p.action = ACTION_TYPE::ALLOW;
	} else if (action == "deny") {
		p.action = ACTION_TYPE::DENY;
	} else if (action == "modify") {
		p.action = ACTION_TYPE::MODIFY;
	}
    	// enabled
    	cout << "Enable this policy? (1=yes, 0=no): ";
    	cin >> p.enabled;
	
	/*
    	// use conditions?
    	cout << "Use conditions? (1=yes, 0=no): ";
    	cin >> p.use_conditions;

    	if (p.use_conditions) {

        	cout << "Condition argument (arg1/arg2/arg3/arg4): ";
        	cin >> p.conditions.field;

        	cout << "Operator (equals/greater/less/contains): ";
        	cin >> p.conditions.operator_;

        	cout << "Condition value (int or string): ";
        	string raw;
        	cin >> raw;
        	// detect int or string
        	try {
        	    	int v = stoi(raw);
        	    	p.conditions.value = v;
        	} catch (...) {
        	    	p.conditions.value = raw;
        	}
    	}
	*/

    	// modify arguments only if modify
    	if (p.action == ACTION_TYPE::MODIFY) {
    	    auto ask_arg = [&](const string &name) -> variant<long, string> {
    	        cout << name << " (value or -1 to skip): ";
    	        string input;
    	        cin >> input;

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

	//if (p.use_conditions) {
	//    	json cond;
	//    	cond["value"] = variant_to_json(p.conditions.value);
	//    	cond["operator"] = p.conditions.operator_;
	//    	cond["field"] = p.conditions.field;
//
	//    	pjson["use_conditions"] = true;
	//    	pjson["conditions"] = json::array({ cond });
	//} else {
	    	pjson["use_conditions"] = false;
	//}

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
		load_policies_from_json();
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

void PolicyEngine::remove_policy() {
	cout << "Enter ID to delete: ";
	int id; cin >> id;

	count--;
}

void PolicyEngine::edit_policy() {
	Policy p;
    	cout << "=== Add New Policy ===\n";

    	// syscall
    	cout << "Enter syscall: ";
    	cin >> p.syscall;

    	// action
	string action;
    	cout << "Action (allow/deny/modify): ";
    	cin >> action;
	
	if (action == "allow") {
		p.action = ACTION_TYPE::ALLOW;
	} else if (action == "deny") {
		p.action = ACTION_TYPE::DENY;
	} else if (action == "modify") {
		p.action = ACTION_TYPE::MODIFY;
	}
    	// enabled
    	cout << "Enable this policy? (1=yes, 0=no): ";
    	cin >> p.enabled;

    	
    	// modify arguments only if modify
    	if (p.action == ACTION_TYPE::MODIFY) {
    	   	auto ask_arg = [&](const string &name) -> variant<long, string> {
    	        	cout << name << " (value or -1 to skip): ";
    	        	string input;
    	        	cin >> input;

    	        	try {
    	        	    return stoi(input);
    	        	} catch (...) {
    	        	    return input;
    	        	}
    		 };

	}

	json j;
	j["id"] = p.id;
	j["syscall"] = p.syscall;
	j["enabled"] = p.enabled;

	if (p.action == ACTION_TYPE::MODIFY) {
	    	j["arguments"] = {
	    	    	{"rdi", variant_to_json(p.args.rdi)},
	    	    	{"rsi", variant_to_json(p.args.rsi)},
	    	    	{"rdx", variant_to_json(p.args.rdx)},
	    	    	{"r10", variant_to_json(p.args.r10)}
	    	};
	}

	ofstream outfile(policy_config);
	outfile << j.dump(4);
	cout << "\nPolicy saved to " << policy_config << "\n";
}