dirs := nulltls openssl
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@; \
	done
