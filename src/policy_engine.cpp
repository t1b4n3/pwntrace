#include "policy_engine.hpp"


unordered_map<int, struct Policy> PolicyEngine::policies;

PolicyEngine::PolicyEngine(const string &config_pathname) {
	config_path = config_pathname;
	load_policies_from_json(config_path);
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
    	load_policies_from_json(config_path);
}

void PolicyEngine::load_policies_from_json(const string &path) {
    	ifstream file(path);
    	json j;
    	file >> j;

	SyscallTable table;

    	for (auto &item : j) {
    	    	Policy p;
    	    	p.id = item["id"];
    	    	p.syscall = item["syscall"];
    	    	p.syscall_no = table.get_syscall_no(item["syscall"]);
    	    	p.action = parse_action(item["action"]);
    	    	p.enabled = item.value("enabled", true);
    	    	p.stub_return = item.value("stub_return", 0);
		
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
				p.conditions.value = cond["value"].get<std::string>();
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
        9, 12, 39, 104, 105, 106, 107, 108, 108, 110, 112, 113, 114, 231, 238, 262, 334, 273, 10, 158, 318, 302, 218, 17, 11
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

