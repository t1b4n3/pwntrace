# PWNTRACE

pwntrace is syscall debugging tool. 

Intercepts syscalls in userspace and it allows security researchers to monitor, modify, and control system calls made by applications in real-time, enabling analysis of malware behavior, testing exploits in controlled environments and understanding program interactions with the operating system

What it does:
- intercepts selected syscalls of a target process and logs and/or forwards them to a proxy.
- policy engine to permit/deny/modify behavior


What can it be used for?
- Reverse Engineering:
	- Dynamic Analysis (behavioral analysisi): Run the binary using this tool and see exactly what the binary does:
	- Malware unpacking and anti-analysis evasion: 

- Exploit Development:
	- Controlled envir for weaponization: If a specific syscall crashes your exploit in lab environment, you can use this proxy to stub out the syscall to always return success, allowing you to focus on developing the rest of the exploit chain.
	- Exploit Primitive Augmentation:
	- Post Exploitation Analysis & forensics: After a successful exploitation, you can trace everything the exploit payload does.
