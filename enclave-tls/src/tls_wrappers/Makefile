dirs := nulltls wolfssl wolfssl-sgx
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@ || exit; \
	done
