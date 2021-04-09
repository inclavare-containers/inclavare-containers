dirs := nullquote sgx-ecdsa sgx-la
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@; \
	done
