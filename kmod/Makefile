CONFIG_DEBUG=n
CONFIG_SASL=n
CONFIG_CN_CACHE=n
CONFIG_PAGES_CACHE=n
CONFIG_BUFFER_CACHE=n
CONFIG_STACK_OPT=y

# all listen sockets share a thread 
CONFIG_SINGLE_DISPATCHER=n

ifeq ($(CONFIG_DEBUG),y)
  DEBFLAGS = -O -Wall -g
else
  DEBFLAGS = -O2
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I $(PWD)/../include

ifeq ($(CONFIG_CN_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_CN_CACHE
endif

ifeq ($(CONFIG_PAGES_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_PAGES_CACHE
endif

ifeq ($(CONFIG_BUFFER_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_BUFFER_CACHE
endif

ifeq ($(CONFIG_STACK_OPT),y)
  EXTRA_CFLAGS += -DCONFIG_STACK_OPT
endif

ifeq ($(CONFIG_SINGLE_DISPATCHER),y)
  EXTRA_CFLAGS += -DCONFIG_SINGLE_DISPATCHER
endif

obj-m	+= kmodhelper.o kmemcache.o

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
		mc_proto.o	\
		mc_connector.o	\
		mc_uparam.o

kmemcache-$(CONFIG_SASL)	+= mc_sasl.o


all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions *.symvers *.order

install:
	install -d $(INSTALLDIR)
	install -m 755 *.ko $(INSTALLDIR)

uninstall:
	rm -f $(INSTALLDIR)/*.ko

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
