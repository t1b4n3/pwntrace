#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdarg.h>  // For va_start, va_arg, va_end
#include <errno.h>   // For errno
#include <string.h>  // For strerror
#include "logging.h"

// Function pointer types
typedef ssize_t (*read_t)(int, const void*, size_t);
typedef ssize_t (*write_t)(int, const void *, size_t);
typedef int (*open_t)(const char *, int, ...);
typedef int (*close_t)(int);

typedef int (*connect_t)(int, const struct sockaddr *, socklen_t); 
typedef void (*exit_t)(); //60

// Real function storage
static read_t real_read = NULL;
static open_t real_open = NULL;
static close_t real_close = NULL;
static connect_t real_connect = NULL;
static write_t real_write = NULL;
static exit_t real_exit = NULL;

// Initialize all at once
__attribute__((constructor)) 
static void init_all() {
	set_logfile_path("./log_syscall.txt");

	real_read = (open_t)dlsym(RTLD_NEXT, "read");
    	real_open = (open_t)dlsym(RTLD_NEXT, "open");
    	real_close = (close_t)dlsym(RTLD_NEXT, "close");
    	real_connect = (connect_t)dlsym(RTLD_NEXT, "connect");
    	real_write = (write_t)dlsym(RTLD_NEXT, "write");

    	if (!real_open) fprintf(stderr, "dlsym failed for open: %s\n", dlerror());
    	if (!real_close) fprintf(stderr, "dlsym failed for close: %s\n", dlerror());
    	if (!real_connect) fprintf(stderr, "dlsym failed for connect: %s\n", dlerror());
    	if (!real_write) fprintf(stderr, "dlsym failed for write: %s\n", dlerror());
}

// Intercepted functions
int open(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    
    log_message(LOG_INFO,"[OPEN] path=%s, flags=%d, mode=%o\n", pathname, flags, mode);
    
    if (!real_open) {
        errno = ENOSYS;
        return -1;
    }
    
    if (flags & O_CREAT) {
        return real_open(pathname, flags, mode);
    } else {
        return real_open(pathname, flags);
    }
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    log_message(LOG_INFO, "[CONNECT] sockfd=%d, addrlen=%d\n", sockfd, addrlen);

    if (addr && addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr_in->sin_addr, ip_str, sizeof(ip_str));
        log_message(LOG_INFO,"  Connecting to: %s:%d\n", ip_str, ntohs(addr_in->sin_port));
    } else if (addr && addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip_str, sizeof(ip_str));
        log_message(LOG_INFO, "  Connecting to: [%s]:%d\n", ip_str, ntohs(addr_in6->sin6_port));
    } else {
        log_message(LOG_WARN,"  Unknown address family: %d\n", addr ? addr->sa_family : -1);
    }
    if (!real_connect) {
        errno = ENOSYS;
        return -1;
    }
    return real_connect(sockfd, addr, addrlen);
}

ssize_t write(int fd, const void *buf, size_t count) {
    printf("[WRITE] fd=%d, count=%zu\n", fd, count);
    
    // Log first few bytes (be careful with binary data)
    if (count > 0 && buf) {
        printf("  Data: ");
        for (size_t i = 0; i < (count < 16 ? count : 16); i++) {
            unsigned char c = ((unsigned char*)buf)[i];
            if (c >= 32 && c < 127) printf("%c", c);
            else printf("\\x%02x", c);
        }
        printf("\n");
    }
    
    if (!real_write) {
        errno = ENOSYS;
        return -1;
    }
    return real_write(fd, buf, count);
}

int close(int fd) {
    printf("[CLOSE] fd=%d\n", fd);
    
    if (!real_close) {
        errno = ENOSYS;
        return -1;
    }
    return real_close(fd);
}