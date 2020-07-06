.PHONY: all install clean uninstall

all:
	$(MAKE) -C rune
	$(MAKE) -C runectl
	$(MAKE) -C shim

install:
	$(MAKE) -C rune install
	$(MAKE) -C runectl install
	$(MAKE) -C shim install

clean:
	$(MAKE) -C rune clean
	$(MAKE) -C runectl clean
	$(MAKE) -C shim clean

uninstall:
	$(MAKE) -C rune uninstall
	$(MAKE) -C runectl uninstall
	$(MAKE) -C shim uninstall
