PREFIX		?= /usr/local
INSTALLDIR	?= $(PREFIX)/kmemcache
KERNELDIR	?= /lib/modules/$(shell uname -r)/build

all: utils module

.PHONY: utils
utils:
	$(MAKE) -C user PWD=$(shell pwd)/user all

.PHONY: module
module:
	$(MAKE) -C kmod KERNELDIR=$(KERNELDIR) PWD=$(shell pwd)/kmod all

clean:
	$(MAKE) -C user clean
	$(MAKE) -C kmod clean

install:
	$(MAKE) -C user INSTALLDIR=$(INSTALLDIR) install
	$(MAKE) -C kmod INSTALLDIR=$(INSTALLDIR) install

uninstall:
	$(MAKE) -C user INSTALLDIR=$(INSTALLDIR) uninstall
	$(MAKE) -C kmod INSTALLDIR=$(INSTALLDIR) uninstall
