verifiers := nullverifier sgx-ecdsa sgx-ecdsa-qve sgx-la
all clean install uninstall:
	for v in $(verifiers); do\
		make -C $$v $@; \
	done;
