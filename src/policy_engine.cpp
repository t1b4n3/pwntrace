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
			for (auto &arg : item["arguments"]) {
				for (auto &kv : arg.items()) {	
					auto &key  = kv.key();
					auto &value =kv.value(); 
					if (value.is_string()) {
						p.arguments.push_back(value.get<string>());
					} else {
						p.arguments.push_back(value.get<int>());
					}
				}
					
			}
		}
		if (item.contains("conditions") && !item["conditions"].empty()) {
			auto &cond = item["conditions"][0];
				
			p.conditions.field = cond["field"];
			p.conditions.operator_ = cond["operator"];
				
			if (cond["value"].is_string()) {
				p.conditions.value = cond["value"].get<string>();
			} else if (cond["value"].is_number_integer()) {
				p.conditions.value = cond["value"].get<int>();
			} else {
			    p.conditions.value = cond["value"].dump();
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


void PolicyEngine::deny_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy) {
	printf("\n[--] DENY : %d - %s\n", policy.syscall_no, policy.syscall.c_str());
	regs.orig_rax = -1;
	regs.rax = policy.stub_return;
	ptrace(PTRACE_SETREGS, target, 0, &regs);
}

bool PolicyEngine::check_conditions(pid_t target, Policy policy, struct user_regs_struct regs) {
	if (policy.conditions.field.empty()) return true;
	long actual_value = 0;
    
	// check arg
    	if (policy.conditions.field == "arg1") {
#if defined(__x86_64__)
        actual_value = regs.rdi;
#elif defined(__i386__)
        actual_value = regs.ebx;
#endif
    	} else if (policy.conditions.field == "arg2") {
#if defined(__x86_64__)
        	actual_value = regs.rsi;
#elif defined(__i386__)
        	actual_value = regs.ecx;
#endif
    	}
    else if (policy.conditions.field == "arg3") {
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

void PolicyEngine::modify_syscall(pid_t target, int syscall_no, struct user_regs_struct regs, Policy policy) {
	if (policy.use_conditions) {
		if (!check_conditions(target, policy, regs)) return;
	}

	ReadMemory read_mem;
	WriteMemory write_mem;

	//string mem_str = read_mem.read_string(target, arg, 256);
	//if (policy.condition != mem_str) return;
	//write_mem.write_string(target, arg, policy.modify);
	//printf("\n[**] MODIFY : %d - %s\n", policy.syscall_no, policy.syscall.c_str());
	//printf("0x%llx : %s -> %s\n", arg, mem_str.c_str(), policy.modify.c_str());
  	// Apply modifications from policy.arguments
    	// Write modified registers back to target process

	// vector<variant<int, string>> arguments;
	auto it = policy.arguments.begin();
	int arg_ = 1;
	for (it; it != policy.arguments.end(); ++it, ++arg_) {
		if (holds_alternative<int>(*it)) {
			int value = get<int>(*it);
			if (value == -1) {
				continue;
			} else {
				switch (arg_) {
					case 1: regs.rdi = value; break;
            				case 2: regs.rsi = value; break;
            				case 3: regs.rdx = value; break;
            				case 4: regs.r10 = value; break;
            				case 5: regs.r8 = value; break;
            				case 6: regs.r9 = value; break;
				}

			}
		} else if (holds_alternative<string>(*it)) {
			switch (arg_) {
				case 1: write_mem.write_string(target, regs.rdi, get<string>(*it)); break;
				case 2: write_mem.write_string(target, regs.rsi, get<string>(*it)); break;
				case 3: write_mem.write_string(target, regs.rdx, get<string>(*it)); break;
				case 4: write_mem.write_string(target, regs.r10, get<string>(*it)); break;
				case 5: write_mem.write_string(target, regs.r8, get<string>(*it)); break;
			}
		}
	}
	ptrace(PTRACE_SETREGS, target, nullptr, &regs);
    	printf("[**] MODIFY: %d - %s\n", policy.syscall_no, policy.syscall.c_str());

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

    	// modify arguments only if modify
    	if (p.action == ACTION_TYPE::MODIFY) {
    	    auto ask_arg = [&](const string &name) -> variant<int, string> {
    	        cout << name << " (value or -1 to skip): ";
    	        string input;
    	        cin >> input;

    	        try {
    	            return stoi(input);
    	        } catch (...) {
    	            return input;
    	        }
    	    };

    	    p.arguments.push_back(ask_arg("arg1"));
    	    p.arguments.push_back(ask_arg("arg2"));
    	    p.arguments.push_back(ask_arg("arg3"));
    	    p.arguments.push_back(ask_arg("arg4"));
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

	if (p.use_conditions) {
	    	json cond;
	    	cond["value"] = variant_to_json(p.conditions.value);
	    	cond["operator"] = p.conditions.operator_;
	    	cond["field"] = p.conditions.field;

	    	pjson["use_conditions"] = true;
	    	pjson["conditions"] = json::array({ cond });
	} else {
	    	pjson["use_conditions"] = false;
	}

	if (p.action == ACTION_TYPE::MODIFY) {
	    	pjson["arguments"] = {
	    	    	{"arg1", variant_to_json(p.arguments[0])},
	    	    	{"arg2", variant_to_json(p.arguments[1])},
	    	    	{"arg3", variant_to_json(p.arguments[2])},
	    	    	{"arg4", variant_to_json(p.arguments[3])}
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

json PolicyEngine::variant_to_json(const variant<int, string> &v) {
    	if (holds_alternative<int>(v))
    		return get<int>(v);
    	return get<string>(v);
}

string PolicyEngine::variant_to_string(const variant<int, string>& v) {
    if (holds_alternative<int>(v))
        return to_string(get<int>(v));

    return get<string>(v);
}



void PolicyEngine::add_commands() {
	auto& policy = GlobalCLI.add_group("policy");

	policy.add("add", "Add new policy", [&](auto args) {
		create_policy();
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
		cout << "ID: " << p.id << endl 
		<< "Syscall Name: " << p.syscall << endl
		<< "Syscall No: " << p.syscall_no << endl
		<< "Action: " << p.action << endl
		<< "Enabled: " << (p.enabled ? "true" : "false") << endl;

		if (p.use_conditions) {
			if (p.action == ACTION_TYPE::MODIFY) {
				cout << "Arguments:";
            			cout << "\n        arg1 = " << variant_to_string(p.arguments[0]);
            			cout << "\n        arg2 = " << variant_to_string(p.arguments[1]);
            			cout << "\n        arg3 = " << variant_to_string(p.arguments[2]);
            			cout << "\n        arg4 = " << variant_to_string(p.arguments[3]);
			}

			cout << "Condtions: ";
			cout << "\n	[" << p.conditions.field << " "
			<< p.conditions.operator_ << " " << variant_to_string(p.conditions.value) << "]" << endl;

		}
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

    	// modify arguments only if modify
    	if (p.action == ACTION_TYPE::MODIFY) {
    	    auto ask_arg = [&](const string &name) -> variant<int, string> {
    	        cout << name << " (value or -1 to skip): ";
    	        string input;
    	        cin >> input;

    	        try {
    	            return stoi(input);
    	        } catch (...) {
    	            return input;
    	        }
    	    };

    	    p.arguments.push_back(ask_arg("arg1"));
    	    p.arguments.push_back(ask_arg("arg2"));
    	    p.arguments.push_back(ask_arg("arg3"));
    	    p.arguments.push_back(ask_arg("arg4"));
    	}

	json j;
	j["id"] = p.id;
	j["syscall"] = p.syscall;
	j["enabled"] = p.enabled;
	if (p.use_conditions) {
		j["use_conditions"] = true;
		j["conditions"] = json::array();


		j["conditions"]["value"] = variant_to_json(p.conditions.value);
		j["conditions"]["operator"] = p.conditions.operator_;
		j["conditions"]["field"] = p.conditions.field;
	} else {
		j["use_conditions"] = false;
	}

	if (p.action == ACTION_TYPE::MODIFY) {
		j["arguments"]["arg1"] = variant_to_json(p.arguments[0]);
		j["arguments"]["arg2"] = variant_to_json(p.arguments[1]);
		j["arguments"]["arg3"] = variant_to_json(p.arguments[2]);
		j["arguments"]["arg4"] = variant_to_json(p.arguments[3]);
	}

	ofstream outfile(policy_config);
	outfile << j.dump(4);
	cout << "\nPolicy saved to " << policy_config << "\n";
}