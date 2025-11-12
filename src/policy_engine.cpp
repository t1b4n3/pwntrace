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
    	    	p.condition = item.value("condition", "None");
    	    	p.modify = item.value("modify", "None");
    	    	p.stub_return = item.value("stub_return", 0);

    	    	policies[p.syscall_no] = p;
    	}
}

bool PolicyEngine::should_trace(int syscall_no) {
    static const unordered_set<int> skip = {
        9, 12, 39, 104, 105, 106, 107, 108, 108, 110, 112, 113, 114, 231, 238, 262,
    };
    return skip.find(syscall_no) == skip.end();
}

Policy PolicyEngine::evaluate(int syscall_no) {
	if (!should_trace(syscall_no)) return {.action = ACTION_TYPE::ALLOW};
	//unordered_map<int, struct Policy> policies;
	auto it = policies.find(syscall_no); 
	if (it == policies.end()) return {.action = ACTION_TYPE::ALLOW};

	//for (vector<Policy>::iterator p = it->second.begin(); p != it->second.end(); ++p) {
	//	if (!p->enabled) continue;
	//	// check if policy has condition
	//	if (!p->condition.empty()) {
	//		regex r(p->condition);
	//		for (auto &a : args) {
	//			if (regex_search(a, r)) return *p;
	//		}
	//	}  else {
	//		return *p;
	//	}
	//}

	Policy &p = it->second;
	if (!p.enabled) return {.action = ACTION_TYPE::ALLOW};

	return p;
}