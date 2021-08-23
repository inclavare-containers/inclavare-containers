PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
#include $(TOP_DIR)/buildenv.mk

######## APP Settings ########

App_Rust_Flags := --release
App_SRC_Files := $(shell find ./ -type f -name '*.rs') $(shell find ./ -type f -name 'Cargo.toml')

App_Rust_Path := $(TOP_DIR)/target/release
App_Name := verdict

.PHONY: all
all: $(App_Name)

######## App Objects ########

$(App_Name): $(App_SRC_Files)
	@cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"

.PHONY: install uninstall clean

PREFIX := /usr/local
BINDIR := $(PREFIX)/bin

install: $(App_Name)
	@install -D -m0755 $(App_Rust_Path)/$(App_Name) "$(BINDIR)"

uninstall:
	@rm -f $(BINDIR)/$(App_Name)

#package:
#	$(MAKE) -C dist package

clean:
	@cargo clean && rm -f Cargo.lock