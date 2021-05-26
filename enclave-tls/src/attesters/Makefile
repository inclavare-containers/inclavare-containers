attesters := nullattester sgx-ecdsa sgx-la
all clean install uninstall:
	for a in $(attesters); do \
		make -C $$a $@; \
	done;
