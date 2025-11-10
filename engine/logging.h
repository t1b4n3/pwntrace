#ifndef LOGS_H
#define LOGS_H

#include <stdio.h>

#define BUFFER_SIZE 1024

typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_DATA,
} LogLevel;

void set_logfile_path(char *path);

void log_message(LogLevel level, const char *format, ...);

#endif