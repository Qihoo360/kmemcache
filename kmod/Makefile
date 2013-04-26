PREFIX = /usr/local
INSTALLDIR = $(PREFIX)/kmemcache

CONFIG_DEBUG=n
CONFIG_SASL=n
CONFIG_PAGES_CACHE=y
CONFIG_BUFFER_CACHE=y
CONFIG_LISTEN_CACHE=y
CONFIG_STACK_OPT=y

ifeq ($(CONFIG_DEBUG),y)
  DEBFLAGS = -O -Wall -g -DCONFIG_DEBUG
else
  DEBFLAGS = -O2
endif

ifeq ($(CONFIG_PAGES_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_PAGES_CACHE
endif

ifeq ($(CONFIG_BUFFER_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_BUFFER_CACHE
endif

ifeq ($(CONFIG_LISTEN_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_LISTEN_CACHE
endif

ifeq ($(CONFIG_STACK_OPT),y)
  EXTRA_CFLAGS += -DCONFIG_STACK_OPT
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I $(PWD)/../include

ifneq ($(KERNELRELEASE),)

obj-m	:= kmodhelper.o connector.o kmemcache.o

kmemcache-y :=	mc_strops.o	\
		mc_buffer.o	\
		mc_hash.o	\
		mc_slabs.o	\
	       	mc_items.o	\
		mc_hashtable.o	\
		mc_stats.o	\
		mc_main.o	\
		mc_worker.o	\
		mc_messenger.o	\
		mc_dispatcher.o	\
		mc_proto_bin.o	\
		mc_proto_txt.o	\
		mc_proto.o

kmemcache-$(CONFIG_SASL)	+= mc_sasl.o


else

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)

all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

endif

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order

install:
	install -d $(INSTALLDIR)
	install -m 755 *.ko $(INSTALLDIR)

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
