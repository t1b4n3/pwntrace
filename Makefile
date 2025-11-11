TARGET = ./build/pwntrace
BUILD_DIR := ./build
SRC_DIRS := ./src

SRCS := $(shell find $(SRC_DIRS) -name '*.cpp')

CC = g++

CFLAGS = -g

$(shell mkdir -p $(BUILD_DIR))


all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET)
clean:
	rm -r $(BUILD_DIR)

.PHONY: all clean