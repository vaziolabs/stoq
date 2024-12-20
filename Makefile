#!/bin/bash

# Determine pkg-config command
PKG_CONFIG := $(shell command -v pkgconf >/dev/null 2>&1 && echo "pkgconf" || echo "pkg-config")
PKG_NAME := $(shell command -v pkgconf >/dev/null 2>&1 && echo "libngtcp2" || echo "ngtcp2")

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -g -O2 -D_GNU_SOURCE
INCLUDES := -I. -I./include $(shell $(PKG_CONFIG) --cflags $(PKG_NAME))
LIBS := $(shell $(PKG_CONFIG) --libs $(PKG_NAME)) -lpthread -lssl -lcrypto

# Directories
BUILD_DIR := build
SRC_DIR := src
INCLUDE_DIR := include

# Source files and objects
SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Binary name
TARGET := $(BUILD_DIR)/stoq

# Default target
.DEFAULT_GOAL := all

all: check_deps $(BUILD_DIR) $(TARGET)

# Check dependencies
check_deps_ubuntu:
	@which pkg-config > /dev/null || (echo "Error: pkg-config not found" && exit 1)
	@pkg-config --exists ngtcp2 || (echo "Error: ngtcp2 development package not found" && exit 1)

check_deps_arch:
	@which pkgconf > /dev/null || (echo "Error: pkgconf not found" && exit 1)
	@pkgconf --exists libngtcp2 || (echo "Error: libngtcp2 development package not found" && exit 1)

# Create build directory
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	@echo "Compiling $<..."
	@$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Link the program
$(TARGET): $(OBJS)
	@echo "Linking $(TARGET)..."
	@$(CC) $(OBJS) $(LIBS) -o $(TARGET)
	@echo "Build successful!"
	@echo "Binary location: $(TARGET)"
	@echo "Usage example: $(TARGET) --mode private --hostname localhost --server localhost"

# Clean build files
clean:
	@echo "Cleaning build files..."
	@rm -rf $(BUILD_DIR)

deps:
	@echo "Determining system type..."
	@if command -v apt-get >/dev/null; then \
		echo "System type: Ubuntu/Debian"; \
		make deps_ubuntu; \
	elif command -v pacman >/dev/null; then \
		echo "System type: Arch Linux"; \
		make deps_arch; \
	else \
		echo "Unsupported system type. Please install the required dependencies manually."; \
		exit 1; \
	fi

# Install dependencies (example for Ubuntu/Debian)
deps_ubuntu:
	@echo "Installing dependencies..."
	@if command -v apt-get >/dev/null; then \
		sudo apt-get update && \
		sudo apt-get install -y \
			build-essential \
			pkg-config \
			libngtcp2-dev; \
	else \
		echo "Please install the required dependencies manually."; \
		exit 1; \
	fi

deps_arch:
	@echo "Installing dependencies..."
	@sudo pacman -S --needed --noconfirm \
		base-devel \
		pkgconf \
		libngtcp2

# Help target
help:
	@echo "Available targets:"
	@echo "  all        - Build the project (default)"
	@echo "  clean      - Remove build files"
	@echo "  deps       - Install dependencies (Ubuntu/Debian)"
	@echo "  help       - Show this help message"

# Phony targets
.PHONY: all check_deps clean deps help

# Build will stop if any command fails
.DELETE_ON_ERROR:

# Keep intermediate files
.PRECIOUS: $(BUILD_DIR)/%.o