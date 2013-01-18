all: umemcached module

.PHONY: umemcached
umemcached:
	$(MAKE) -C user

.PHONY: module
module:
	$(MAKE) -C kmod

install:
	$(MAKE) -C user install
	$(MAKE) -C kmod install

clean:
	$(MAKE) -C user clean
	$(MAKE) -C kmod clean
