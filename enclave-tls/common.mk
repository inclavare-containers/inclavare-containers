CC ?= gcc
GO ?= go
INSTALL ?= install
DEBUG ?= 1

SRCDIR := $(TOPDIR)/src
BINDIR := $(TOPDIR)/bin
SAMPLES_DIR := $(TOPDIR)/samples
CLIENT_DIR := $(SAMPLES_DIR)/enclave-tls-client
SERVER_DIR := $(SAMPLES_DIR)/enclave-tls-server

ENCLAVE_TLS_PREFIX ?= /opt/enclave-tls
ENCLAVE_TLS_LIBDIR := $(ENCLAVE_TLS_PREFIX)/lib
ENCLAVE_TLS_INCDIR := $(ENCLAVE_TLS_PREFIX)/include
ENCLAVE_QUOTES_LIBDIR := $(ENCLAVE_TLS_LIBDIR)/enclave_quotes
TLS_WRAPPERS_LIBDIR := $(ENCLAVE_TLS_LIBDIR)/tls_wrappers
