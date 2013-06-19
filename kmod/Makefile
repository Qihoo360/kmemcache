CONFIG_DEBUG=n

# sasl, not implementation
CONFIG_SASL=n

# connector request cache
CONFIG_CN_CACHE=n

# out of memory managment
CONFIG_OOM=y

# verbose log level control
CONFIG_VERBOSE=y

# thread statistics lock
CONFIG_SLOCK=n

ifeq ($(CONFIG_DEBUG),y)
  DEBFLAGS = -O -Wall -g -DCONFIG_DEBUG
endif

EXTRA_CFLAGS += $(DEBFLAGS)
EXTRA_CFLAGS += -I$(PWD)/../include

ifeq ($(CONFIG_CN_CACHE),y)
  EXTRA_CFLAGS += -DCONFIG_CN_CACHE
endif

ifeq ($(CONFIG_OOM),y)
  EXTRA_CFLAGS += -DCONFIG_OOM
endif

ifeq ($(CONFIG_VERBOSE),y)
  EXTRA_CFLAGS += -DCONFIG_VERBOSE
endif

ifeq ($(CONFIG_SLOCK),y)
  EXTRA_CFLAGS += -DCONFIG_SLOCK
endif

obj-m	+= kmctest.o kmemcache.o

kmctest-y := mc_strops.o kmodtest.o

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
		mc_uparam.o	\
		mc_msg.o

kmemcache-$(CONFIG_SASL)	+= mc_sasl.o
kmemcache-$(CONFIG_OOM)		+= mc_oom.o


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
