#ifndef LOGGING_H
#define LOGGING_H
#include <cstring>
#include <cstdio>

#define BUFFER_SIZE 1024

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_DATA,
    LOG_RESULT,
} LogLevel;

void set_logfile_path(const char *path);

void log_message(LogLevel level, const char *format, ...);

#endif