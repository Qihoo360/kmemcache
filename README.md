kmemcache
=========

kmemcache is a high-performance, distributed memory object caching system, generic in nature,
but intended for use in speeding up dynamic web applications by alleviating database load.

kmemcache is derived from memcached-v1.4.15, exactly it is a linux kernel memcached,
and aims at quicker response and higher performance.

Current Limitations
-------------------
kmemcache has now implemented all most major features of memcached, including the complete binary
and text protocols, based on tcp, udp and unix domain communication protocols, slab allocation 
dynamically rebalanced, hash table expansion and so on.

The programming interface remains consistent with memcached. Clients using memcached can easily 
connected to kmemcache, without modification. You could also easily add the kmemcache server to
your cluster of memcached servers.

The following are some features that have not been implemented yet:  
* SASL

Environment
-----------
x86_32/x86_64	
kernel: [2.6.32, 3.2]	
other versions have not been tested

Building, Running & Testing
---------------------------

	[root@jgli]# tar xjf kmemcache.tar.bz2
	[root@jgli]# make
	[root@jgli]# insmod kmod/kmemcache.ko
	[root@jgli]# user/umemcached -h
	[root@jgli]# user/umemcached -p 11213
	[root@jgli]# apt-get install libmemcached
	[root@jgli]# memslap --servers=localhost:11213

Contributing
------------
Want to contribute? You are so welcome! Any reported bugs, feedback, and pulling requests are encouraged!

Website
-------
Official memcached: http://www.memcached.org/	
Test tools: http://libmemcached.org/libMemcached.html	
Something about kmemcache from my blog: http://blog.sina.com.cn/u/3289939872
