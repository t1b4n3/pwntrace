#include "./tracer.hpp"

struct user_regs_struct regs;

void print_syscall(SYSCALL sys, pid_t target, PolicyEngine policy_engine) {
	ReadMemory read_mem;
	SyscallTable table;
	string syscall_name;
	string data;

#if defined(__x86_64__)
	if (!policy_engine.should_trace(regs.orig_rax)) return;
	if (sys == SYSCALL_ENTRY) {
		cout << endl;
		log_message(LOG_RESULT, "PID %d SYSCALL entry: num=%llu args=(0x%llx,0x%llx,0x%llx,0x%llx,0x%llx,0x%llx)",
                	target,
                	(unsigned long long)regs.orig_rax,
                	(unsigned long long)regs.rdi,
                	(unsigned long long)regs.rsi,
                	(unsigned long long)regs.rdx,
                	(unsigned long long)regs.r10,
                	(unsigned long long)regs.r8,
                	(unsigned long long)regs.r9);
		
		if (regs.orig_rax == 0) {
			printf("[+] Syscall %llu - %s\n(0x%llx) Enter Data : 0x%llx -> ", 
				regs.orig_rax, table.get_syscall_name(regs.orig_rax).c_str(), regs.rdi, regs.rsi);
		} else if (regs.orig_rax == 1) {
			printf("[+] Syscall %llu - %s\n( rdi=0x%llx rsi=0x%llx rdx=0x%llx )\nWrote Data : 0x%llx -> %s\n",
			regs.orig_rax, table.get_syscall_name(regs.orig_rax).c_str(), 
			regs.rdi, regs.rsi, regs.rdx, regs.rsi, 
			read_mem.read_string(target, regs.rsi).c_str());
		} else if (regs.orig_rax == 2) {
			printf("[+] Syscall %llu - %s\nOpening : %s Flags : %d",
				regs.orig_rax, table.get_syscall_name(regs.orig_rax).c_str(),
				read_mem.read_string(target, regs.rsi, 256), regs.rdx
				);
		} else if (regs.orig_rax == 3) {
			printf("[+] Syscall %llu - %s\nClosing : 0x%llx\n",
				regs.orig_rax, table.get_syscall_name(regs.orig_rax).c_str(), 
				regs.rax
				);
		}
		else {
			printf("[+] Syscall %llu - %s\n( rdi=0x%llx rsi=0x%llx rdx=0x%llx ) mem[%s]\n", 
				regs.orig_rax, table.get_syscall_name(regs.orig_rax).c_str(), regs.rdi,
				regs.rsi, regs.rdx, read_mem.read_string(target, regs.rsi, 256).c_str()
			);	
		}
	} else {
		log_message(LOG_RESULT, "PID %d SYSCALL exit:  num=%llu => ret=0x%llx",
        		target,
        		(unsigned long long)regs.orig_rax,
        		(unsigned long long)regs.rax);

		printf("[-] ret=0x%llx\n", regs.rax);

	}	
#elif defined(__i386__) // x86
	if (!policy_engine.should_trace(regs.orig_eax)) return;

	if (sys == SYSCALL_ENTRY) {
		log_message(LOG_RESULT, "PID %d SYSCALL entry: num=%lu args=(0x%lx,0x%lx,0x%lx,0x%lx,0x%lx,0x%lx)",
            		target,
            		(unsigned long)regs.orig_eax,
            		(unsigned long)regs.ebx,
            		(unsigned long)regs.ecx,
            		(unsigned long)regs.edx,
            		(unsigned long)regs.esi,
            		(unsigned long)regs.edi,
            		(unsigned long)regs.ebp);

		printf("[+] Syscall %d - %s\n( rdi=%d rsi=%p rdx=%d ) mem[%s]\n", 
			regs.orig_eax, table.get_syscall_name(regs.orig_eax).c_str(), regs.ebx,
			regs.eci, regs.edx, read_mem.read_string(target, regs.eci, 256).c_str()
		);	

	} else {
            	log_message(LOG_RESULT, "PID %d SYSCALL exit:  num=%lu => ret=0x%lx",
            	        target,
            	        (unsigned long)regs.orig_eax,
            	        (unsigned long)regs.eax);

		printf("[-] ret=0x%llx\n", regs.eax);
	}

#else
        log_message(LOG_INFO, "PID %d SYSCALL exit (unknown arch)", target);
#endif
}


void tracer(pid_t pid, string pathname) {
	log_message(LOG_INFO, "Pwntrace");
	SyscallTable table;


	int status;
	pid_t target;
	bool launched_child = false;
	if (pid != -1 && pathname.empty()) {
		log_message(LOG_INFO, "Attaching pid: %d", pid);
		if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
			log_message(LOG_ERROR, "PTRACE_ATTACH failed: %s", strerror(errno));
			exit(1);
		}
		target = pid;

		if (waitpid(target, &status, 0) == -1) {
			log_message(LOG_ERROR, "waitpid(after attach) failed: %s", strerror(errno));
			exit(1);
		}

		if (WIFEXITED(status) || WIFSIGNALED(status)) {
			log_message(LOG_ERROR, "Target died after attach | status=0x%x", status);
			exit(1);
		}

		log_message(LOG_INFO, "Attached: target stopped | status=0x%x", status);

	} else if (!pathname.empty()) {
		log_message(LOG_INFO, "Starting process: %s", pathname.c_str());
		pid_t child = fork();
		
		if (child == -1) {
			log_message(LOG_ERROR, "fork failed: %s", strerror(errno));
			exit(1);
		} else if (child == 0) {
			if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
				log_message(LOG_ERROR, "PTRACE_TRAME failed");
				exit(0);
			}
			execl(pathname.c_str(), pathname.c_str(), NULL);
			log_message(LOG_ERROR, "execl failed: %s", strerror(errno));
			exit(1);
		} else {
			target = child;
			launched_child = true;
			
			if (waitpid(target, &status, 0) == -1) {
				log_message(LOG_ERROR, "waitpid(after fork) failed: %s", strerror(errno));
				exit(1);
			}

			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				log_message(LOG_ERROR, "Target died after attach | status=0x%x", status);
				exit(1);
			}

			if (ptrace(PTRACE_GETREGS, child, NULL, &regs) == -1) {
				log_message(LOG_ERROR, "PTRACE_GETREGS failed");
				exit(0);
			}
			log_message(LOG_INFO, "Launched child stopped (status=0x%x)", status);
		}
	} 	

	
	// Print initial regsiters
	if (ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1) {
		log_message(LOG_WARN, "PTRACE_GETREGS failed: %s", strerror(errno));
	}

	// set options to help detect syscall stops
	if (ptrace(PTRACE_SETOPTIONS, target, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK) == -1) {
    		log_message(LOG_WARN, "PTRACE_SETOPTIONS failed (continuing): %s", strerror(errno));	
	}	


	if (ptrace(PTRACE_SYSCALL, target, NULL, NULL) == -1) {
		log_message(LOG_ERROR, "PTRACE_SYSCALL inital resume failed: %s", strerror(errno));
		if (!launched_child) ptrace(PTRACE_DETACH, target, NULL, NULL);
		exit(1);
	}

	bool in_syscall = false;
	bool is_syscall_stop = false;
	int signal = 0;
	int syscall_no = -1;
	while (true) {
		if (waitpid(target, &status, 0) == -1) { 
			log_message(LOG_ERROR, "waitpid filed inside loop");
			break;
		}

		if (WIFEXITED(status)) {
        		log_message(LOG_INFO, "Target %d exited with status %d", target, WEXITSTATUS(status));
        		break;
    		}
    		if (WIFSIGNALED(status)) {
    		    	log_message(LOG_INFO, "Target %d killed by signal %d", target, WTERMSIG(status));
    		    	break;
    		}
 
		if (WIFSTOPPED(status)) {
        		signal = WSTOPSIG(status);

        		// Detect syscall stop: SIGTRAP | 0x80 when TRACESYSGOOD is set
        		is_syscall_stop = false;
        		if (signal == (SIGTRAP | 0x80)) is_syscall_stop = true;
        		else if (signal == SIGTRAP) {
        			    // treat plain SIGTRAP as possible syscall stop or other ptrace event
        			    // We assume it's a syscall stop if PTRACE_SYSCALL was used.
        			    is_syscall_stop = true;
        		}
        		if (is_syscall_stop) {
        	    		// read registers
        	    		if (ptrace(PTRACE_GETREGS, target, NULL, &regs) == -1) {
        	        		log_message(LOG_ERROR, "PTRACE_GETREGS failed during trace: %s", strerror(errno));
        	        		// try to continue or break
        	        		if (ptrace(PTRACE_SYSCALL, target, NULL, NULL) == -1) {
        	        		    	log_message(LOG_ERROR, "PTRACE_SYSCALL continue failed: %s", strerror(errno));
        	        		    	break;
        	       			}
        	       			continue;
				}
#if defined(__x86_64__)
				syscall_no = regs.orig_rax;
#elif defined(__i386__) // x86
				syscall_no = regs.orig_eax;
#endif
				Policy policy = policy_engine.evaluate(syscall_no);

				switch (policy.action) {
					case ACTION_TYPE::DENY:
						// skip syscall and ret fake return
						if (!in_syscall) {
							in_syscall = true;
							policy_engine.deny_syscall(target, policy.syscall_no, regs, policy);
						} else {
							in_syscall = false;
						}
						break;
					case ACTION_TYPE::MODIFY:
						if (!in_syscall) {
							in_syscall = true;
							policy_engine.modify_syscall(target, policy.syscall_no, regs, policy);
						} else {
							in_syscall = false;
						}
					default:
						//  do nothing let syscall execute normally | ACTION_TYPE::ALLOW:
						if (!in_syscall) {
                					// syscall entry
                					in_syscall = true;
							print_syscall(SYSCALL_ENTRY, target, policy_engine);
            					} else {
                					// syscall exit
                					in_syscall = false;
                					print_syscall(SYSCALL_EXIT, target, policy_engine);
            					}
						break;
				
				}

				if (ptrace(PTRACE_SYSCALL, target, NULL, NULL) == -1) {
					log_message(LOG_ERROR, "PTRACE_SYSCALL continue failed: %s", strerror(errno));
                			break;
				}
				continue;
			} else {
				log_message(LOG_INFO, "PID %d stopped by signal %d, forwarding", target, signal);
            			if (ptrace(PTRACE_SYSCALL, target, NULL, signal) == -1) {
                			log_message(LOG_ERROR, "PTRACE_SYSCALL (forward signal) failed: %s", strerror(errno));
                			break;
				}
            		}
            		continue;
		}
	}
	
	if (!launched_child) {
    		if (ptrace(PTRACE_DETACH, target, NULL, NULL) == -1) {
    			log_message(LOG_WARN, "PTRACE_DETACH failed: %s", strerror(errno));
    		}
	}
	log_message(LOG_INFO, "Pwntrace DONE");
}
