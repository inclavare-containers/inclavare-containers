PROJDIR := $(shell readlink -f ..)
TOP_DIR := .
#include $(TOP_DIR)/buildenv.mk

######## APP Settings ########

Opa_SRC_Files := opaEngine.go
App_Rust_Flags := --release
App_SRC_Files := $(shell find app/ -type f -name '*.rs') $(shell find app/ -type f -name 'Cargo.toml')

App_Rust_Path := $(TOP_DIR)/app/target/release
Opa_Lib_Path := $(TOP_DIR)/app/src/policyEngine/opa
App_Name := verdictd
Opa_Name := libopa.so

.PHONY: all
all: $(App_Name)

######## App Objects ########

opa:
	@cd $(Opa_Lib_Path) && go build -o $(Opa_Name) -buildmode=c-shared $(Opa_SRC_Files)

enclave-tls:
	$(MAKE) -C $(PROJDIR)/enclave-tls SGX=1 install

$(App_Name): opa enclave-tls $(App_SRC_Files)
	@cd app && RUSTFLAGS="-C link-args=-Wl,-rpath=/opt/enclave-tls/lib:/usr/local/lib:$(PROJDIR)/verdictd/lib,--enable-new-dtags" cargo build $(App_Rust_Flags)
	@echo "Cargo  =>  $@"
	mkdir -p bin lib
	cp $(App_Rust_Path)/$(App_Name) $(TOP_DIR)/bin
	cp $(Opa_Lib_Path)/$(Opa_Name) $(TOP_DIR)/lib

.PHONY: install uninstall clean

PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib

install: $(App_Name)
	@install -D -m0755 $(TOP_DIR)/bin/$(App_Name) "$(BINDIR)"
	@install -D -m0755 $(TOP_DIR)/lib/$(Opa_Name) "$(LIBDIR)"

uninstall:
	@rm -f $(BINDIR)/$(App_Name)
	@rm -f $(LIBDIR)/$(Opa_Name)

#package:
#	$(MAKE) -C dist package

clean:
	@rm -rf $(TOP_DIR)/bin/ $(TOP_DIR)/lib/ $(Opa_Lib_Path)/libopa.*
	@cd app && cargo clean && rm -f Cargo.lock