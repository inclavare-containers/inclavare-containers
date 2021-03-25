dirs := nullcrypto wolfcrypt
all clean install uninstall:
	for d in $(dirs); do \
	  make -C $$d $@ || exit; \
	done
