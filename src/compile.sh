#!/bin/bash

g++ -g -no-pie -fPIE main.cpp ../includes/logging.cpp ./tracer.cpp ./syscall_table.cpp ./read_memory.cpp -o pwntrace