dirs := nullcrypto wolfcrypt wolfcrypt-sgx openssl
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@; \
	done
