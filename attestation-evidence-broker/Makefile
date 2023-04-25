PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
CUR_DIR := $(shell pwd)
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin

TARGET_DIR := ./target
BIN_NAME := aeb

DEBUG ?=
ifdef DEBUG
    release :=
    TARGET_DIR := $(TARGET_DIR)/debug
else
    release := --release
    TARGET_DIR := $(TARGET_DIR)/release
endif

all:
	$(RUST_FLAGS) cargo build $(release)

TARGET := $(TARGET_DIR)/$(BIN_NAME)

install:
	install -D -m0755 $(TARGET) $(BINDIR)

uninstall:
	rm -f $(BINDIR)/$(BIN_NAME)

clean:
	cargo clean && rm -f Cargo.lock

help:
	@echo "build: make [DEBUG=1]"
